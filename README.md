# Windows 11 Lite

This project helps you build a lightweight Windows 11 Lite ISO that removes TPM checks, hardware requirements, and the mandatory Microsoft account requirement. It also skips unnecessary Windows setup steps during installation and removes preinstalled bloatware while keeping the system fully usable.

This is a simplified and safer fork of [tiny11builder](https://github.com/ntdevlabs/tiny11builder). It avoids issues like “Managed by your organization” and users can still adjust settings or reinstall removed apps whenever they want. The script works entirely with Microsoft’s own deployment tools such as DISM and supports generating a clean, ready‑to‑install ISO image.

# How to Build a Windows 11 Lite ISO

## Step 1:

Download the files `autounattend.xml` and `Windows11Lite.ps1` and place them in the following directory: `D:/setup`

## Step 2:

Right-click the official Windows 11 ISO downloaded from Microsoft and select `Mount`

Windows will create a virtual DVD drive. In this guide, the mounted ISO is assumed to appear as drive `E:`.
If your system assigns a different letter, use that one.

## Step 3: Open **PowerShell** or **Terminal** as **Administrator**, then execute:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

```powershell
D:/setup/Windows11Lite.ps1 -ISO E
```

> Replace `E` with the actual drive letter of your mounted ISO.

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-DB61A2?style=for-the-badge&logo=github-sponsors&logoColor=white)](https://nvbangg.github.io/#donate)

<div align="center">

[![Followers](https://img.shields.io/github/followers/nvbangg?label=Follow%20my%20GitHub&logo=github)](https://github.com/nvbangg) &nbsp; [![Stars](https://img.shields.io/github/stars/nvbangg/Windows11Lite?label=Star%20this%20repo&logo=github)](https://github.com/nvbangg/Windows11Lite) &nbsp; ![Visitors](https://api.visitorbadge.io/api/visitors?path=Windows11Lite&countColor=blue&style=flat&labelStyle=none)<br><img src="https://nvbangg.github.io/assets/gifs/follow_star_github.gif" height="100">

</div>