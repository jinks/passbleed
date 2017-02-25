# Passbleed
Passbleed checks your exported KeePass database against the CloudBleed list
found [here](https://github.com/pirate/sites-using-cloudflare).

## Download
Head to the [Releases](https://github.com/jinks/passbleed/releases) page and grab a copy for your OS (only the Linux release was tested)

or:
```
go get github.com/jinks/passbleed
```
(required Go 1.8+)

## Usage
1. Export your KeePass database to CSV format with either [KeePass](http://keepass.info/) v2.35, [KeePassX](https://www.keepassx.org/) v2.0.3 or [KeepassXC](https://keepassxc.org/) v2.1.2
2. Grab a copy of [sorted\_unique\_cf.txt](https://github.com/pirate/sites-using-cloudflare) (use the [master.zip](https://github.com/pirate/sites-using-cloudflare/archive/master.zip) to save some bandwidth)
3. Run `./passbleed keepass.csv sorted_unique_cf.txt`

## Caveats
* All processing happens in RAM. On my machine it uses about 400 MB
* __The exported CSV contains sensitive data.__ Put it on an encrypted disk and/or _securely_ delete it when you're done.

## Changelog
v1.1:
* Added 1Password CSV support
* Sorted output
