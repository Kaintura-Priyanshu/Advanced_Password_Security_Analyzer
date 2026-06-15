# Advanced Password Security Analyzer

Advanced Password Security Analyzer is a Python-based cybersecurity tool that evaluates password strength using real-world attack techniques rather than simple length checks. It analyzes entropy, estimates brute-force crack time, detects common password weaknesses, and provides actionable security recommendations.

## Features

### Password Strength Analysis

* Classifies passwords as Weak, Medium, or Strong.

### Entropy Calculation

* Measures password randomness using information theory.

### Crack Time Estimation

* Estimates how long a modern attacker would take to brute-force the password.

### Common Password Detection

Detects passwords commonly found in leaked credential databases such as:

* password
* 123456
* qwerty
* admin

### Keyboard Pattern Detection

Identifies predictable keyboard walks such as:

* qwerty
* asdfgh
* 123456
* 1q2w3e

### Personal Information Detection

Checks whether the password contains:

* Name
* Username
* Birth Year

### Repeated Character Detection

Detects weak repetition patterns such as:

* aaaaaa
* 111111
* aabbcc

### Sequential Character Detection

Identifies predictable sequences such as:

* abc
* 123
* xyz

### Security Recommendations

Provides personalized suggestions for improving password strength.

### Detailed Security Report

Generates a complete password security assessment including:

* Strength Score
* Entropy
* Crack Time
* Issues Found
* Recommendations
* Final Verdict

## Technologies Used

* Python 3
* Regular Expressions (Regex)
* Information Theory (Entropy)
* Cybersecurity Best Practices

## Example Output

```text
=============================================
         PASSWORD SECURITY REPORT
=============================================

Strength Score      : 88/100
Password Strength   : Strong
Entropy             : 78.42 bits
Estimated Crack Time: 1,245 Years

Detected Issues:
 No issues found.

Recommendations:
 Excellent password!

Final Verdict:
 Password is highly secure.
=============================================
```

## Security Considerations

* Passwords are processed locally.
* No password data is stored.
* No internet connection is required.
* Hidden password input using getpass.
* Input validation prevents malformed inputs.

## Learning Outcomes

This project demonstrates:

* Password Security Analysis
* Secure Coding Practices
* Entropy-Based Risk Assessment
* Pattern Recognition
* Cybersecurity Fundamentals
* Python Programming

## Future Enhancements

* Breached Password Database Integration
* Password Generator Module
* Password History Analysis
* GUI Version (Tkinter/PyQt)
* Export Security Reports to PDF
* Multi-Factor Authentication Recommendations

