# HSTS Redirect Check
This tool will help you to solve issues when using `HSTS` with URL Redirections.

![image](https://user-images.githubusercontent.com/9881407/62499366-b5acbf80-b7e2-11e9-9d3e-99acc51ade16.png)

# Story behind the tool
This tool was initialy written to debug issues created by the way my domain manager is managing their URL Redirections.

They have clearly no support for `HSTS` and they have decided to stay silent to my questions.

# Usage
This tool can be used on any domains, not only the one that caused me issues :grin:.

What the tool will do:
 * Parse the given host to search for existing sub domains
 * Assign extracted domains and sub domains to targets list
 * Make some `DNS` queries on the generated targets
 * Collect `HTTP` headers from targets
 * Analyze collected `HTTP` headers
 * Generate result from the analysis
 
# Privacy
This tool won't store any data, won't do any `call to home`, won't send me back any data. You can use it safely.
 
# Credits
Just myself and a friend who prefered to stay unknown and I respect his decision.
 
# Contribute
If you feel this tool is really useful and want to improve it, then feel free to contribute by sending pull requests or create new issues.

# Contact
You can reach me on Twitter using [@Jiab77](https://twitter.com/Jiab77)
