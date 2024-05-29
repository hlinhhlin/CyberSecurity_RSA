# CyberSecurity_RSA

AESpaAdmission System is a secure admission software designed to protect applicant data through advanced cryptographic techniques. It features secure registration and login, employing 2048-bit RSA encryption for passwords and 128-bit AES encryption for personal information such as names, surnames, addresses, emails, and telephone numbers. The system generates and securely manages RSA and AES keys for each user, stores encrypted user data in a JSON file, and utilizes environment variables for sensitive key storage. With a user-friendly GUI, AESpa facilitates easy registration and login, ensuring data confidentiality, integrity, and secure user interactions throughout the admission process.

Project Summary
  This project implements a secure admission system using a combination of RSA and AES encryption algorithms. The primary goal is to ensure secure storage and transmission of applicant credentials and personal data during the registration and login processes. The system is built using Python, leveraging various cryptographic functions for key generation, encryption, and decryption to maintain data confidentiality and integrity.
  
  • Cryptographic requirements:
  
  – Implemented RSA Algorithms
  * Key Generation: RSA key pairs are generated with a default size of 2048 bits, providing strong security for encryption and decryption processes.
  * Encryption/Description Algorithms:
   · Data: RSA is used to encrypt user passwords during the signup process. The encrypted passwords are stored securely in the database.
  – Implemented AES Algorithms:
  * Symmetric Encryption Algorithms: AES (Advanced Encryption Standard) is used for encrypting personal information such as name, surname, address, email, and telephone number. The AES key size is 128 bits (16 bytes), and encryption is performed using AES in EAX mode to provide both confidentiality and authentication.
  * DataHandling: The system encrypts personal information during the signup process and decrypts it during the login process to display the user’s data.
  * Performance: AES encryption and decryption are efficient for the small sized data typical in user credentials and personal information storage.

  • Application Requirements:
  
  – Useof RSAandAESfor Security Services:
  * Authentication: RSA encryption is used to encrypt and securely store user passwords. During the login process, the stored encrypted password is decrypted and compared with the provided password to authenticate the user.
  * Confidentiality: AES encryption ensures the confidentiality of personal information. The AES key used for encryption is securely generated and stored.
  – Data Storage:
  * Thesystem handles textual data input through a GUI. It encrypts the user’s password and personal information during the registration process and decrypts it during the login process
