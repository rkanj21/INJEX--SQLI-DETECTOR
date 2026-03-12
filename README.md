SQL Injection and Command Injection Detection System using NLP

Overview
This project presents a machine learning and NLP based security system designed to detect and prevent SQL Injection (SQLi) and Command Injection attacks in web applications. These attacks are among the most common vulnerabilities in modern web systems and can allow attackers to manipulate databases or execute unauthorized commands on servers.

The system analyzes user input queries using Natural Language Processing techniques and machine learning classification models to determine whether the input is safe or malicious. By detecting suspicious patterns before execution, the system helps improve the security and reliability of web applications.

Problem Statement
Traditional rule based security filters often fail to detect newly crafted or obfuscated injection attacks. Attackers can bypass simple keyword filters using variations in syntax or encoding. Therefore this project aims to develop a smart detection mechanism using NLP and machine learning that can identify malicious queries based on their structure and linguistic patterns rather than relying only on static rules.

Objectives
Detect SQL Injection and Command Injection attacks in user inputs
Use Natural Language Processing to analyze query structures
Train a machine learning classifier on malicious and legitimate query datasets
Provide real time detection and prevention before the query reaches the backend database
Improve web application security by identifying suspicious patterns

System Architecture
The system follows a multi stage pipeline

User Input Collection
Input is taken from the web interface

Preprocessing
Cleaning and tokenization of the input query

POS Tagging
Using the NLTK library to understand the structure of the query

Feature Extraction
Converting text data into machine learning features using vectorization techniques

Machine Learning Classification
The model predicts whether the query is safe or malicious

Security Filtering
Suspicious queries are blocked before reaching the database

Technologies Used
Programming Language Python
Web Framework Flask
Natural Language Processing NLTK
Machine Learning Scikit learn
Data Processing Pandas and NumPy
Visualization and Evaluation Matplotlib and Seaborn

Key Features
Detection of SQL Injection attacks such as OR 1 equals 1 and UNION SELECT queries
Detection of Command Injection patterns including shell operators like && || ; and |
NLP based analysis using POS tagging
Machine learning classification for intelligent attack detection
Real time query validation in a web environment
Performance evaluation using accuracy precision recall and confusion matrix

Dataset
The model is trained using a modified dataset of SQL injection queries and normal user inputs. The dataset contains labeled examples of normal SQL queries malicious SQL injection patterns and command injection attempts. This dataset helps the machine learning model learn to differentiate between legitimate database queries and malicious attack patterns.

Model Training
Data preprocessing and cleaning
Tokenization and NLP analysis
Feature extraction using vectorization techniques
Training a classification model using Scikit learn
Evaluation using confusion matrix ROC curve precision recall and classification report

Project Workflow
User submits input through the web interface:
![WhatsApp Image 2026-03-12 at 1 16 45 PM (1)](https://github.com/user-attachments/assets/ac43fbf6-1283-460a-ad12-6520434d30a1)

Input text is preprocessed and analyzed using NLP
![WhatsApp Image 2026-03-12 at 1 16 47 PM](https://github.com/user-attachments/assets/253780ef-01e8-426f-959c-ddf62c763826)

Features are extracted from the input query
The trained machine learning model predicts whether the query is malicious
![WhatsApp Image 2026-03-12 at 1 16 46 PM (1)](https://github.com/user-attachments/assets/e05e90c2-9254-4253-9862-e2c0ed188b49)
If malicious the query is blocked and flagged as an attack
![WhatsApp Image 2026-03-12 at 1 16 45 PM (2)](https://github.com/user-attachments/assets/c4fb24ab-e3ce-490a-b085-7e27dc1a0a37)
![WhatsApp Image 2026-03-12 at 1 16 46 PM](https://github.com/user-attachments/assets/8f110b6c-89d8-42fa-ace4-f899f18a11e9)

Applications
Secure web applications
E commerce platforms
Banking and financial systems
Authentication and login systems
API request validation

Future Improvements
Integrating deep learning models for higher detection accuracy
Expanding datasets with more real world attack samples
Deploying the system in cloud based web environments
Integrating with web application firewalls

Conclusion
This project demonstrates how Natural Language Processing and Machine Learning can be applied to improve web security by detecting SQL and command injection attacks. By analyzing the structure and patterns of user inputs the system provides an intelligent layer of protection against malicious queries and enhances the safety of web applications.

Author
Final Year Project
Computer Science Engineering
