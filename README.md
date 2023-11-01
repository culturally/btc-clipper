# Bitcoin Clipper 
Simple Bitcoin Stealer By Manipulating Clipboard with Sandbox,Task Manager,VM detection.
This repo was more of a fun project than actual serious malware.
## DISCLAIMER

This code and any associated documentation are provided for educational and informational purposes only. It is intended to showcase techniques for identifying virtual machines and sandbox environments, which can be useful for understanding system contexts, security research, and threat detection.

However, it is essential to understand that the use of this code or any derivative work for malicious or unethical purposes is strictly prohibited and illegal. Unauthorized intrusion, tampering with systems, or violating privacy can result in legal consequences and ethical concerns.

# INFO
## Task Manager Interaction
While the code monitors the Task Manager's activity, it may not be fully effective when Task Manager is open. One potential approach to enhance this functionality involves injecting the code into the Task Manager process to obscure its presence. However, to maintain a balance between stealth and anti-detection measures, the code is divided into two parts: 'simple.cpp' and 'main.cpp.' but 'main.cpp.' has obviously way more detection on virustotal.

## 'simple.cpp'
The 'simple.cpp' component is designed with a minimal detection mechanism, ensuring that the clipboard manipulation works without modifying the system's startup settings. This approach aims to maintain a lower profile and reduce the chances of detection.
# Admin Privilege Check:

The code checks if the current user has administrative privileges. This information can be crucial for understanding the system's context.
# Task Manager Detection:

It checks whether the Task Manager is open. Task Manager is often used to monitor running processes and can be an indicator of a virtual environment.
Move to Programs Directory:

The code attempts to move the executable to the Windows "Programs" directory. This action is often performed by malware to persist on a system.
Virtual Machine Detection:

The code examines the system for various artifacts and services associated with virtualization software like VirtualBox, VMware, and others. The presence of these artifacts can suggest a virtual machine environment.
# Sandbox Detection:

The code employs a multifaceted approach to detect sandboxes:
It checks for the presence of specific sandbox-related DLLs (e.g., SxIn.dll, SbieDll.dll).
It examines known sandbox processes.
It determines if virtualization is enabled (Intel VT-x or AMD-V).
It checks for the presence of a debugger.
It inspects environment variables associated with sandbox software.
It analyzes low-level system information (e.g., CPU vendor string) to detect virtualized or sandboxed environments.
Clipboard Manipulation:

The code monitors the clipboard and searches for Bitcoin addresses. If detected, it replaces the addresses with a predefined one. This functionality may be used to prevent cryptocurrency address swapping attacks.
# User Interface:

The code provides a graphical user interface using a hidden console window. It ensures the program is run with administrative privileges and, if not, displays an error message.
