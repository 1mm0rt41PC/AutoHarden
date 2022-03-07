<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Issues][issues-shield]][issues-url]
[![GPLv2 License][license-shield]][license-url]



<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/1mm0rt41PC/HowTo/tree/master/Harden/Windows">
    <img src="logo.png" alt="Logo" width="80" height="80" alt="Icon from https://www.flaticon.com/free-icon/pixels_423099?term=protect&page=1&position=23">
  </a>

  <h3 align="center">AutoHarden</h3>

  <p align="center">
    A awesome script that reinforces Windows security with many options
  </p>
</p>



<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
* [Build](#build)
* [Roadmap](#roadmap)
* [Notes](#notes)



<!-- ABOUT THE PROJECT -->
## About The Project

There are many great hardening script available on GitHub, however, I didn't find one that really suit my needs so I created this enhanced one.

Here's why:
* One script for different types of use: pentest, home, work, ... Choose your environement at the setup.
* A script that makes sure the configuration doesn't change
* A script that checks the health status of Windows
* A script to manage a group of machines without a Domain
* A script that updates and self-checks itself. So if github is compromised, a hacker won't be able to make any changes to the script.

Of course, no one script will serve all projects since your needs may be different. So I'll be adding more in the near future. You may also suggest changes by forking this repo and creating a pull request or opening an issue.

A list of commonly used resources that I find helpful are listed in the acknowledgements.



<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

* At least Powershell version 2



### Installation

1. Open a CMD.exe (or a powershell.exe) with administrator privileges
2. Run the following command
```ps1
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://github.com/1mm0rt41PC/HowTo/raw/master/Harden/Windows/AutoHarden_RELEASE.ps1');"
```
3. Answers to a few parameterization questions



<!-- BUILD -->
## Build
To merge all ps1 into `AutoHarden_RELEASE.ps1`, use the `build.ps1`
This script will create your own CA for script security
```ps1
powershell -exec bypass -nop -File .\build.ps1
```



<!-- ROADMAP -->
## Roadmap

- [ ] Block auto rules in the Windows firewall
- [ ] Check writable path in `$path` and in `C:\Program Files`
- [ ] Check writable services and tasks



<!-- NOTES -->
## Notes
* All the configuration is stored in `C:\Windows\AutoHarden\`




[contributors-shield]: https://img.shields.io/github/contributors/1mm0rt41PC/HowTo.svg?style=flat-square
[contributors-url]: https://github.com/1mm0rt41PC/HowTo/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/1mm0rt41PC/HowTo.svg?style=flat-square
[forks-url]: https://github.com/1mm0rt41PC/HowTo/network/members
[stars-shield]: https://img.shields.io/github/stars/1mm0rt41PC/HowTo.svg?style=flat-square
[stars-url]: https://github.com/1mm0rt41PC/HowTo/stargazers
[issues-shield]: https://img.shields.io/github/issues/1mm0rt41PC/HowTo.svg?style=flat-square
[issues-url]: https://github.com/1mm0rt41PC/HowTo/issues
[license-shield]: https://img.shields.io/github/license/1mm0rt41PC/HowTo.svg?style=flat-square
[license-url]: https://github.com/1mm0rt41PC/HowTo/blob/master/LICENSE
