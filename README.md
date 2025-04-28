## Winbox Authentication Testing Tool (bruteforce) ⚔️

* A research tool for cybersecurity researchers and redteam to test MikroTik Winbox authentication.
* Designed for authorized testing to strengthen device security.

## Legal Warning:  🛡️

* Unauthorized use breaks laws like
  - **Russia**: Статья 272 УК РФ
  - **USA**: Computer Fraud and Abuse Act (CFAA)
  - **EU**: GDPR Art.32/Network and Information Systems Directive
* The authors and developers are not responsible for your actions!*

Stay Ethical: Use it to secure, not to harm. You’re responsible for legal use; the author isn’t liable for misuse.

Credits: Uses an elliptic curve implementation from MarginResearch/mikrotik_authentication, Copyright 2022 Margin Research, under the Apache License, Version 2.0 (2004). See LICENSE and NOTICE.

## To get started, use the following algorithm:
```sh
cd nekrotik/
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
cd src/ && chmod +x nekrotik.py
# For test single password
./nekrotik.py --ip 172.17.0.2 --username admin --password "admin"
# For bruteforce use wordlist
./nekrotik.py --ip 172.17.0.2 --username admin --dict /tmp/password --output brute.log
```
