# Third-party notices

Keel's untrusted terminal renderer embeds `@xterm/headless` 6.0.0 and
`@xterm/addon-serialize` 0.14.0 from the xterm.js project. Both are licensed
under the MIT License.

Copyright (c) 2017-2019, The xterm.js authors
(https://github.com/xtermjs/xterm.js)

Copyright (c) 2014-2016, SourceLair Private Company
(https://www.sourcelair.com)

Copyright (c) 2012-2013, Christopher Jeffrey
(https://github.com/chjj/)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## Components downloaded during setup

`keel setup` downloads the following components on the user's machine to
build the local runtime and guest image. They are not included in, or
redistributed by, this repository; each is used under its own license or
terms. See [Pinned artifacts](docs/ARTIFACTS.md) for versions and sources.

| Component | License or terms |
|---|---|
| Linux kernel (Alpine `linux-virt`) | GPL-2.0 |
| Alpine Linux packages in the guest image, including Chromium, Node.js, Python, Git, tmux, gcc, Rust, and Go | Each package's own license, as published by Alpine Linux |
| Claude Code | Anthropic's terms for Claude Code |
| `agent-browser` (vercel-labs) | Apache-2.0 |
| Deno | MIT |
| vmette | MIT |

Rust crate dependencies are listed in `Cargo.lock`, and their licenses are
checked by `cargo deny check licenses` against `deny.toml`.
