use regex::Regex;
use std::collections::HashMap;
use std::fmt;

const EXCLUDE_PATTERNS: [(&'static str, &'static str); 1] = [("bash", r"[[:cntrl:]]\[([0-9]{1,2};)?([0-9]{1,2})?m")];

const PATTERNS: [(&'static str, &'static str); 15] = [
  ("markdown_url", r"\[[^]]*\]\(([^)]+)\)"),
  ("url", r"(?P<match>(https?://|git@|git://|ssh://|ftp://|file:///)[^ ]+)"),
  (
    "diff_summary",
    r"diff --git a/([.\w\-@~\[\]]+?/[.\w\-@\[\]]++) b/([.\w\-@~\[\]]+?/[.\w\-@\[\]]++)",
  ),
  ("diff_a", r"--- a/([^ ]+)"),
  ("diff_b", r"\+\+\+ b/([^ ]+)"),
  ("docker", r"sha256:([0-9a-f]{64})"),
  ("path", r"(?P<match>([.\w\-@$~\[\]]+)?(/[.\w\-@$\[\]]+)+)"),
  ("color", r"#[0-9a-fA-F]{6}"),
  ("uid", r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  ("ipfs", r"Qm[0-9a-zA-Z]{44}"),
  ("sha", r"[0-9a-f]{7,40}"),
  ("ip", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
  // `[A-f]` was a RANGE, not a set of hex letters: A-f spans 0x41-0x66, so it
  // also matched `[`, `\`, `]`, `^`, `_` and a backtick, and hinted things like
  // `6:[A`. Narrowed to the letters an address can actually contain.
  ("ipv6", r"[A-Fa-f0-9:]+:+[A-Fa-f0-9:]+[%\w\d]+"),
  ("address", r"0x[0-9a-fA-F]+"),
  ("number", r"[0-9]{4,}"),
];

#[derive(Clone)]
pub struct Match<'a> {
  pub x: i32,
  pub y: i32,
  pub pattern: &'a str,
  pub text: &'a str,
  pub hint: Option<String>,
}

impl<'a> fmt::Debug for Match<'a> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "Match {{ x: {}, y: {}, pattern: {}, text: {}, hint: <{}> }}",
      self.x,
      self.y,
      self.pattern,
      self.text,
      self.hint.clone().unwrap_or("<undefined>".to_string())
    )
  }
}

impl<'a> PartialEq for Match<'a> {
  fn eq(&self, other: &Match) -> bool {
    self.x == other.x && self.y == other.y
  }
}

pub struct State<'a> {
  pub lines: &'a Vec<&'a str>,
  alphabet: &'a str,
  regexp: &'a Vec<&'a str>,
  exclude: Vec<String>,
  exclude_regexp: Vec<String>,
}

impl<'a> State<'a> {
  pub fn new(lines: &'a Vec<&'a str>, alphabet: &'a str, regexp: &'a Vec<&'a str>) -> State<'a> {
    State {
      lines,
      alphabet,
      regexp,
      exclude: Vec::new(),
      exclude_regexp: Vec::new(),
    }
  }

  /// Names from PATTERNS to drop entirely, comma separated. `--regexp` can only
  /// ADD a pattern, so without this there is no way to stop a built-in whose
  /// hints are always noise on a given screen: `ipv6` matches the clock time
  /// `3:54`, `number` matches every `100644` file mode in a diff header.
  pub fn exclude(mut self, names: &str) -> State<'a> {
    self.exclude = names
      .split(',')
      .map(|name| name.trim().to_string())
      .filter(|name| !name.is_empty())
      .collect();
    self
  }

  /// Extra patterns that are matched and SKIPPED PAST without being hinted,
  /// joining the two EXCLUDE_PATTERNS above. This is the only way to suppress
  /// junk that a useful pattern produces, so the pattern itself has to stay:
  /// the `path` built-in reads the `</span>` in HTML output as the path `/span`,
  /// and `path` is far too useful to drop. The regex crate has no lookbehind,
  /// so `(?<!<)/\w+` is not an option either.
  pub fn exclude_regexp(mut self, patterns: &[&str]) -> State<'a> {
    self.exclude_regexp = patterns.iter().map(|p| p.to_string()).collect();
    self
  }

  pub fn matches(&self, reverse: bool, unique: bool) -> Vec<Match<'a>> {
    let mut matches = Vec::new();

    // The third element is whether a win gets a hint. False means "consume the
    // match and move on", which is how an exclude suppresses a pattern it
    // cannot be allowed to delete.
    let exclude_patterns = EXCLUDE_PATTERNS
      .iter()
      .map(|tuple| (tuple.0, Regex::new(tuple.1).unwrap(), false))
      .chain(
        self
          .exclude_regexp
          .iter()
          .map(|regexp| ("exclude", Regex::new(regexp).expect("Invalid exclude regexp"), false)),
      )
      .collect::<Vec<_>>();

    let custom_patterns = self
      .regexp
      .iter()
      .map(|regexp| ("custom", Regex::new(regexp).expect("Invalid custom regexp"), true))
      .collect::<Vec<_>>();

    let patterns = PATTERNS
      .iter()
      .filter(|tuple| !self.exclude.iter().any(|name| name == tuple.0))
      .map(|tuple| (tuple.0, Regex::new(tuple.1).unwrap(), true))
      .collect::<Vec<_>>();

    // This order determines the priority of pattern matching
    let all_patterns = [exclude_patterns, custom_patterns, patterns].concat();

    for (index, line) in self.lines.iter().enumerate() {
      let mut chunk: &str = line;
      let mut offset: i32 = 0;

      loop {
        // For this line we search which patterns match, all of them.
        let submatches = all_patterns
          .iter()
          .filter_map(|tuple| match tuple.1.find_iter(chunk).nth(0) {
            Some(m) => Some((tuple.0, tuple.1.clone(), tuple.2, m)),
            None => None,
          })
          .collect::<Vec<_>>();

        // Then, we search for the match with the lowest index
        let first_match_option = submatches.iter().min_by(|x, y| x.3.start().cmp(&y.3.start()));

        if let Some(first_match) = first_match_option {
          let (name, pattern, emit, matching) = first_match;
          let text = matching.as_str();

          if let Some(captures) = pattern.captures(text) {
            let captures: Vec<(&str, usize)> = if let Some(capture) = captures.name("match") {
              [(capture.as_str(), capture.start())].to_vec()
            } else if captures.len() > 1 {
              captures
                .iter()
                .skip(1)
                .filter_map(|capture| capture)
                .map(|capture| (capture.as_str(), capture.start()))
                .collect::<Vec<(&str, usize)>>()
            } else {
              [(matching.as_str(), 0)].to_vec()
            };

            // An excluded match is still consumed, so it cannot be re-matched
            // by a later pattern -- that is the point for bash colour
            // sequences, and it is what makes an exclude regexp suppress the
            // junk a pattern we are keeping would otherwise emit.
            if *emit {
              for (subtext, substart) in captures.iter() {
                matches.push(Match {
                  x: offset + matching.start() as i32 + *substart as i32,
                  y: index as i32,
                  pattern: name,
                  text: subtext,
                  hint: None,
                });
              }
            }

            chunk = chunk.get(matching.end()..).expect("Unknown chunk");
            offset += matching.end() as i32;
          } else {
            panic!("No matching?");
          }
        } else {
          break;
        }
      }
    }

    let alphabet = super::alphabets::get_alphabet(self.alphabet);
    let mut hints = alphabet.hints(matches.len());

    // This looks wrong but we do a pop after
    if !reverse {
      hints.reverse();
    } else {
      matches.reverse();
      hints.reverse();
    }

    if unique {
      let mut previous: HashMap<&str, String> = HashMap::new();

      for mat in &mut matches {
        if let Some(previous_hint) = previous.get(mat.text) {
          mat.hint = Some(previous_hint.clone());
        } else if let Some(hint) = hints.pop() {
          mat.hint = Some(hint.to_string().clone());
          previous.insert(mat.text, hint.to_string().clone());
        }
      }
    } else {
      for mat in &mut matches {
        if let Some(hint) = hints.pop() {
          mat.hint = Some(hint.to_string().clone());
        }
      }
    }

    if reverse {
      matches.reverse();
    }

    matches
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn split(output: &str) -> Vec<&str> {
    output.split("\n").collect::<Vec<&str>>()
  }

  fn texts<'a>(matches: &'a [Match<'a>]) -> Vec<&'a str> {
    matches.iter().map(|m| m.text).collect()
  }

  #[test]
  fn exclude_drops_a_builtin_by_name() {
    // The ipv6 pattern reads a clock time as an address: 3 + : + 5 + 4.
    let lines = split("done 3:54 PM");
    let custom = [].to_vec();

    let kept = State::new(&lines, "abcd", &custom).matches(false, false);
    assert_eq!(texts(&kept), vec!["3:54"]);

    let dropped = State::new(&lines, "abcd", &custom)
      .exclude("ipv6")
      .matches(false, false);
    assert!(dropped.is_empty());
  }

  #[test]
  fn exclude_takes_a_list_and_ignores_spacing() {
    let lines = split("mode 100644 at 3:54");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom)
      .exclude(" number , ipv6 ")
      .matches(false, false);

    assert!(results.is_empty());
  }

  #[test]
  fn exclude_leaves_the_other_patterns_alone() {
    let lines = split("see /etc/hosts at 3:54");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom)
      .exclude("ipv6")
      .matches(false, false);

    assert_eq!(texts(&results), vec!["/etc/hosts"]);
  }

  #[test]
  fn an_unknown_exclude_name_is_a_no_op() {
    let lines = split("done 3:54 PM");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom)
      .exclude("nosuchpattern")
      .matches(false, false);

    assert_eq!(texts(&results), vec!["3:54"]);
  }

  #[test]
  fn exclude_regexp_suppresses_junk_from_a_pattern_we_keep() {
    // `path` reads the closing tag as the path `/span`, and path is far too
    // useful to drop wholesale -- the real path on the same line must survive.
    let lines = split("<span>x</span> in /etc/hosts");
    let custom = [].to_vec();

    let kept = State::new(&lines, "abcd", &custom).matches(false, false);
    assert_eq!(texts(&kept), vec!["/span", "/etc/hosts"]);

    let suppressed = State::new(&lines, "abcd", &custom)
      .exclude_regexp(&["</\\w+>"])
      .matches(false, false);
    assert_eq!(texts(&suppressed), vec!["/etc/hosts"]);
  }

  #[test]
  fn exclude_regexp_wins_a_tie_against_a_custom_pattern() {
    // Same start column: the exclude list is concatenated first, and min_by
    // keeps the first of equal minimums.
    let lines = split("console.log(x)");
    let custom = ["(?P<match>[\\w.]+\\.log)"].to_vec();

    let kept = State::new(&lines, "abcd", &custom).matches(false, false);
    assert_eq!(texts(&kept), vec!["console.log"]);

    let suppressed = State::new(&lines, "abcd", &custom)
      .exclude_regexp(&["console\\.log"])
      .matches(false, false);
    assert!(suppressed.is_empty());
  }

  #[test]
  fn ipv6_no_longer_matches_bracket_characters() {
    // `[A-f]` was a range spanning 0x41-0x66, so it swallowed `[`, `\`, `]`,
    // `^`, `_` and a backtick.
    let lines = split("row 6:[Alpha]");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert!(
      !texts(&results).iter().any(|t| t.contains('[')),
      "ipv6 matched a bracket: {:?}",
      texts(&results)
    );
  }

  #[test]
  fn ipv6_still_matches_an_address() {
    let lines = split("bound to fe80::1ff:fe23:4567:890a here");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(texts(&results), vec!["fe80::1ff:fe23:4567:890a"]);
  }

  #[test]
  fn match_reverse() {
    let lines = split("lorem 127.0.0.1 lorem 255.255.255.255 lorem 127.0.0.1 lorem");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 3);
    assert_eq!(results.first().unwrap().hint.clone().unwrap(), "a");
    assert_eq!(results.last().unwrap().hint.clone().unwrap(), "c");
  }

  #[test]
  fn match_unique() {
    let lines = split("lorem 127.0.0.1 lorem 255.255.255.255 lorem 127.0.0.1 lorem");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, true);

    assert_eq!(results.len(), 3);
    assert_eq!(results.first().unwrap().hint.clone().unwrap(), "a");
    assert_eq!(results.last().unwrap().hint.clone().unwrap(), "a");
  }

  #[test]
  fn match_docker() {
    let lines = split("latest sha256:30557a29d5abc51e5f1d5b472e79b7e296f595abcf19fe6b9199dbbc809c6ff4 20 hours ago");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 1);
    assert_eq!(
      results.get(0).unwrap().text,
      "30557a29d5abc51e5f1d5b472e79b7e296f595abcf19fe6b9199dbbc809c6ff4"
    );
  }

  #[test]
  fn match_bash() {
    let lines = split("path: [32m/var/log/nginx.log[m\npath: [32mtest/log/nginx-2.log:32[mfolder/.nginx@4df2.log");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 3);
    assert_eq!(results.get(0).unwrap().text, "/var/log/nginx.log");
    assert_eq!(results.get(1).unwrap().text, "test/log/nginx-2.log");
    assert_eq!(results.get(2).unwrap().text, "folder/.nginx@4df2.log");
  }

  #[test]
  fn match_paths() {
    let lines = split("Lorem /tmp/foo/bar_lol, lorem\n Lorem /var/log/boot-strap.log lorem ../log/kern.log lorem");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 3);
    assert_eq!(results.get(0).unwrap().text.clone(), "/tmp/foo/bar_lol");
    assert_eq!(results.get(1).unwrap().text.clone(), "/var/log/boot-strap.log");
    assert_eq!(results.get(2).unwrap().text.clone(), "../log/kern.log");
  }

  #[test]
  fn match_routes() {
    let lines = split("Lorem /app/routes/$routeId/$objectId, lorem\n Lorem /app/routes/$sectionId");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 2);
    assert_eq!(results.get(0).unwrap().text.clone(), "/app/routes/$routeId/$objectId");
    assert_eq!(results.get(1).unwrap().text.clone(), "/app/routes/$sectionId");
  }

  #[test]
  fn match_home() {
    let lines = split("Lorem ~/.gnu/.config.txt, lorem");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 1);
    assert_eq!(results.get(0).unwrap().text.clone(), "~/.gnu/.config.txt");
  }

  #[test]
  fn match_slugs() {
    let lines = split("Lorem dev/api/[slug]/foo, lorem");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 1);
    assert_eq!(results.get(0).unwrap().text.clone(), "dev/api/[slug]/foo");
  }

  #[test]
  fn match_uids() {
    let lines = split("Lorem ipsum 123e4567-e89b-12d3-a456-426655440000 lorem\n Lorem lorem lorem");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 1);
  }

  #[test]
  fn match_shas() {
    let lines = split("Lorem fd70b5695 5246ddf f924213 lorem\n Lorem 973113963b491874ab2e372ee60d4b4cb75f717c lorem");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 4);
    assert_eq!(results.get(0).unwrap().text.clone(), "fd70b5695");
    assert_eq!(results.get(1).unwrap().text.clone(), "5246ddf");
    assert_eq!(results.get(2).unwrap().text.clone(), "f924213");
    assert_eq!(
      results.get(3).unwrap().text.clone(),
      "973113963b491874ab2e372ee60d4b4cb75f717c"
    );
  }

  #[test]
  fn match_ips() {
    let lines = split("Lorem ipsum 127.0.0.1 lorem\n Lorem 255.255.10.255 lorem 127.0.0.1 lorem");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 3);
    assert_eq!(results.get(0).unwrap().text.clone(), "127.0.0.1");
    assert_eq!(results.get(1).unwrap().text.clone(), "255.255.10.255");
    assert_eq!(results.get(2).unwrap().text.clone(), "127.0.0.1");
  }

  #[test]
  fn match_ipv6s() {
    let lines = split("Lorem ipsum fe80::2:202:fe4 lorem\n Lorem 2001:67c:670:202:7ba8:5e41:1591:d723 lorem fe80::2:1 lorem ipsum fe80:22:312:fe::1%eth0");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 4);
    assert_eq!(results.get(0).unwrap().text.clone(), "fe80::2:202:fe4");
    assert_eq!(
      results.get(1).unwrap().text.clone(),
      "2001:67c:670:202:7ba8:5e41:1591:d723"
    );
    assert_eq!(results.get(2).unwrap().text.clone(), "fe80::2:1");
    assert_eq!(results.get(3).unwrap().text.clone(), "fe80:22:312:fe::1%eth0");
  }

  #[test]
  fn match_markdown_urls() {
    let lines = split("Lorem ipsum [link](https://github.io?foo=bar) ![](http://cdn.com/img.jpg) lorem");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 2);
    assert_eq!(results.get(0).unwrap().pattern.clone(), "markdown_url");
    assert_eq!(results.get(0).unwrap().text.clone(), "https://github.io?foo=bar");
    assert_eq!(results.get(1).unwrap().pattern.clone(), "markdown_url");
    assert_eq!(results.get(1).unwrap().text.clone(), "http://cdn.com/img.jpg");
  }

  #[test]
  fn match_urls() {
    let lines = split("Lorem ipsum https://www.rust-lang.org/tools lorem\n Lorem ipsumhttps://crates.io lorem https://github.io?foo=bar lorem ssh://github.io");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 4);
    assert_eq!(results.get(0).unwrap().text.clone(), "https://www.rust-lang.org/tools");
    assert_eq!(results.get(0).unwrap().pattern.clone(), "url");
    assert_eq!(results.get(1).unwrap().text.clone(), "https://crates.io");
    assert_eq!(results.get(1).unwrap().pattern.clone(), "url");
    assert_eq!(results.get(2).unwrap().text.clone(), "https://github.io?foo=bar");
    assert_eq!(results.get(2).unwrap().pattern.clone(), "url");
    assert_eq!(results.get(3).unwrap().text.clone(), "ssh://github.io");
    assert_eq!(results.get(3).unwrap().pattern.clone(), "url");
  }

  #[test]
  fn match_addresses() {
    let lines = split("Lorem 0xfd70b5695 0x5246ddf lorem\n Lorem 0x973113tlorem");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 3);
    assert_eq!(results.get(0).unwrap().text.clone(), "0xfd70b5695");
    assert_eq!(results.get(1).unwrap().text.clone(), "0x5246ddf");
    assert_eq!(results.get(2).unwrap().text.clone(), "0x973113");
  }

  #[test]
  fn match_hex_colors() {
    let lines = split("Lorem #fd7b56 lorem #FF00FF\n Lorem #00fF05 lorem #abcd00 lorem #afRR00");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 4);
    assert_eq!(results.get(0).unwrap().text.clone(), "#fd7b56");
    assert_eq!(results.get(1).unwrap().text.clone(), "#FF00FF");
    assert_eq!(results.get(2).unwrap().text.clone(), "#00fF05");
    assert_eq!(results.get(3).unwrap().text.clone(), "#abcd00");
  }

  #[test]
  fn match_ipfs() {
    let lines = split("Lorem QmRdbNSxDJBXmssAc9fvTtux4duptMvfSGiGuq6yHAQVKQ lorem Qmfoobar");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 1);
    assert_eq!(
      results.get(0).unwrap().text.clone(),
      "QmRdbNSxDJBXmssAc9fvTtux4duptMvfSGiGuq6yHAQVKQ"
    );
  }

  #[test]
  fn match_process_port() {
    let lines =
      split("Lorem 5695 52463 lorem\n Lorem 973113 lorem 99999 lorem 8888 lorem\n   23456 lorem 5432 lorem 23444");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 8);
  }

  #[test]
  fn match_diff_a() {
    let lines = split("Lorem lorem\n--- a/src/main.rs");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 1);
    assert_eq!(results.get(0).unwrap().text.clone(), "src/main.rs");
  }

  #[test]
  fn match_diff_b() {
    let lines = split("Lorem lorem\n+++ b/src/main.rs");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 1);
    assert_eq!(results.get(0).unwrap().text.clone(), "src/main.rs");
  }

  #[test]
  fn match_diff_summary() {
    let lines = split("diff --git a/samples/test1 b/samples/test2");
    let custom = [].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 2);
    assert_eq!(results.get(0).unwrap().text.clone(), "samples/test1");
    assert_eq!(results.get(1).unwrap().text.clone(), "samples/test2");
  }

  #[test]
  fn priority() {
    let lines = split("Lorem [link](http://foo.bar) ipsum CUSTOM-52463 lorem ISSUE-123 lorem\nLorem /var/fd70b569/9999.log 52463 lorem\n Lorem 973113 lorem 123e4567-e89b-12d3-a456-426655440000 lorem 8888 lorem\n  https://crates.io/23456/fd70b569 lorem");
    let custom = ["CUSTOM-[0-9]{4,}", "ISSUE-[0-9]{3}"].to_vec();
    let results = State::new(&lines, "abcd", &custom).matches(false, false);

    assert_eq!(results.len(), 9);
    assert_eq!(results.get(0).unwrap().text.clone(), "http://foo.bar");
    assert_eq!(results.get(1).unwrap().text.clone(), "CUSTOM-52463");
    assert_eq!(results.get(2).unwrap().text.clone(), "ISSUE-123");
    assert_eq!(results.get(3).unwrap().text.clone(), "/var/fd70b569/9999.log");
    assert_eq!(results.get(4).unwrap().text.clone(), "52463");
    assert_eq!(results.get(5).unwrap().text.clone(), "973113");
    assert_eq!(
      results.get(6).unwrap().text.clone(),
      "123e4567-e89b-12d3-a456-426655440000"
    );
    assert_eq!(results.get(7).unwrap().text.clone(), "8888");
    assert_eq!(results.get(8).unwrap().text.clone(), "https://crates.io/23456/fd70b569");
  }
}
