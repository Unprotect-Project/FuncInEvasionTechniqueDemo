# FuncIn Unprotect Evasion Technique Demo

![Banner](Assets/banner.png)

## Description

This demonstration showcases the utilization of FuncIn evasion technique for spawning a remote shell. Instead of embedding the remote shell code directly within the loader, the entire remote shell function is transmitted over the network as a Just-In-Time (JIT) compiled shellcode. Subsequently, it is executed on a dedicated thread of the loader.

This project serves as a template for both practicing and comprehending how malware authors employ advanced techniques to create highly compact and optimized malware. Furthermore, these techniques introduce additional complexity to the reverse engineering process. Unlike conventional methods where the final payloads are directly embedded inside the loader or stored elsewhere (Ex: web server, third part file), this approach involves transmitting them over the network.

The modular nature of the malware, with the final payloads not being directly included in the loader, enhances its evasiveness. The transmitted payloads may also be optionally encrypted or obfuscated, adding an extra layer of defense against detection and analysis. Additionally, the malware may be configured to listen for specific events or behaviors before triggering the transmission of the payload.

## Video

![Video Demo](Assets/video.gif)

## Feature

* Remote Shell
* Support both x86-32 and x86-64 host process.
* Full interoperability between x86-32 Controller and x86-64 Loader and vis-versa.
* Designed to be easily extended in feature for practicing and learning purpose.

## WIP

* x86-64 Remote Shell Shellcode
* Demonstrate with additional programming languages (Next is Python)

## Changelog

## 13 Dec 2023

* Release (Delphi Loader & Controller)

## Greetings go to

- [Keystone Engine](https://www.keystone-engine.org)

For their awesome open-source engine which facilitate shellcode development and maintenance.

## Disclaimer

🇺🇸 All source code and projects shared on this Github account by Unprotect are provided "as is" without warranty of any kind, either expressed or implied. The user of this code assumes all responsibility for any issues or legal liabilities that may arise from the use, misuse, or distribution of this code. The user of this code also agrees to release Unprotect from any and all liability for any damages or losses that may result from the use, misuse, or distribution of this code.

By using this code, the user agrees to indemnify and hold Unprotect harmless from any and all claims, liabilities, costs, and expenses arising from the use, misuse, or distribution of this code. The user also agrees not to hold Unprotect responsible for any errors or omissions in the code, and to take full responsibility for ensuring that the code meets the user's needs.

This disclaimer is subject to change without notice, and the user is responsible for checking for updates. If the user does not agree to the terms of this disclaimer, they should not use this code.

**Unprotect refers to the team dedicated to the maintenance and development of projects under the Unprotect umbrella.**
