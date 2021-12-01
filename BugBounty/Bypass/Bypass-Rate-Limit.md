# OTP Login Rate Limit Bypass
- Search for web applications or mobile apps that allow the user to login using the OTP https://www.exploit-db.com/google-hacking-database
- On the login page, I entered my mobile number and requested the one-time password
- I received a 6 digit number on my phone but I tried entering the wrong 6 digits in the application 
- After opening the network tab of the Firefox browser or Burp Suite to monitor the web request
- Should get an error message that says ‘Invalid OTP’
- Resend the same invalid OTP several times to check if there is any rate-limit
- After X# of attempts should receive “number of tries exceeded” message
- Forward the request to the Burp Repeater and start tampering with each parameter
- Try changing Random Number Values or adding to the parameter values (try adding spaces to the end or changing digits) to udid or country code or mobile number fields and try the OTP again. 
- If it lets you continue trying OTPs then you have found a small flaw that would allow an attacker to brute force an OTP 



# Account Lockout Bypass
- Bruteforce password field
- Account locked
- Register Account with same username (Blocked one)
- Account already exists 
- Clicked below login button
- Try with real password
- Login successful -> Lockout bypass
