# cartomancer-github

GitHub REST API client and unified diff parser for the [Cartomancer](https://github.com/jrollin/cartomancer) PR review pipeline.

## Components

- `GitHubClient` — fetch PR metadata, fetch diffs, post PR reviews with inline comments, post summary comments. Single-retry on 5xx for all requests.
- `parse_diff` — hand-written unified diff parser for GitHub's diff format
- `is_line_in_diff` — check if a finding line falls within a diff hunk (for inline vs off-diff comment placement)
- `PrMetadata` / `ReviewComment` — GitHub API request/response types
- `PullRequestEvent` / `should_review` — webhook payload parsing

## Usage

This crate is used internally by the cartomancer binary. It is not intended for direct use.

## License

MIT
