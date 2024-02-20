# CodeSearchDemo

## Related Links

* [Maldev Academy Code Search](https://search.maldevacademy.com/)

* [Maldev Academy](https://maldevacademy.com/)

* [Maldev Academy Twitter](https://twitter.com/maldevacademy)

## Building a Loader

This repository showcases the [Maldev Academy Code Search](https://search.maldevacademy.com/) which was used to build two projects.

1. **Payload Builder:** This project is responsible for generating an encrypted payload. It does this by utilizing the following snippets from the code search service:
    * `Decryption Key Brute Force` - Print a function that encrypts a key and then decrypts it by brute force.
    * `AES Encryption Using The CTAES Library` - Use the CTAES library to implement AES 256 CBC encryption.
    * `Read a File From Disk (ASCII)` - Read a file from the disk.
    * `Random Key Generation` - Generate a random buffer with a specified size without using WinAPIs in the generation process.
    * `Print a Hexadecimal Array` - Write a specified memory buffer to the console as a C-style hexadecimal array. 

2. **Shellcode Loader:** This project injects and executes the payload after decrypting it. It does this by utilizing the following snippets from the code search.
    * `AES Decryption Using The CTAES Library` - Use the CTAES library to perform AES 256 CBC decryption.
    * `Process Creation With Block DLL Policy` - Leveraging HellsHall to execute indirect syscalls and invoking NtCreateUserProcess to create a process with blocking non-Microsoft DLLs policy enabled.
    * `Remote Mapping Injection Via HellsHall` - Remote mapping injection using indirect syscalls provided by HellsHall.
    * `Delaying Execution With No APIs` - Introduce a delay in code execution without the use of WinAPIs.

## Payload Builder Video Demo

[![Builder VD](https://github.com/Maldev-Academy/CodeSearchDemo/assets/111295429/71d9d39f-605b-462d-8293-624dbc37c7fa)](https://vimeo.com/914305790?share=copy)

## Shellcode Loader

[![Builder VD](https://github.com/Maldev-Academy/CodeSearchDemo/assets/111295429/385ba599-97c7-4b4d-9c9f-111f3d7189ce)](https://vimeo.com/914301843?share=copy)

