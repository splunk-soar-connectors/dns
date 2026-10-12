# Contributing

For more information about contributing to Splunk SOAR Apps please take a look at our app [Contribution Guide](https://github.com/splunk-soar-connectors/.github/blob/main/.github/CONTRIBUTING.md)!

## Local SDK builds

Clone this repository into a directory named `soar_dns`:

```sh
git clone git@github.com:splunk-soar-connectors/dns.git ~/git/soar_dns
cd ~/git/soar_dns
git checkout dns-sdkify
uv sync --locked
uv run soarapps package build . --output-file phantom_dns.tgz
```

SDK 6.1.2 imports the app using the build directory's name. A directory named
`dns` conflicts with dnspython's `dns` package. Building from `soar_dns` gives
the app a separate import namespace without changing the GitHub repository,
SOAR package identifier, or runtime entry point.

CI jobs and other tools that generate manifests or packages must also use a
directory with a distinct name. Coordinate the shared workflow changes before
removing the existing package path extension.
