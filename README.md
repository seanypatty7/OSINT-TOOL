# OSINT-TOOL
Python tool to aggregate various OSINT reports on given artifact.

This is a very rough first draft to just see if it will work. Still need to work on input validation/error handling, updating GUI, changing/adding reports.

You need to update the configsample.py file with your own API keys and rename file to config.py to match code in main.py. Alternatively, change variable names of config imports to configSample.

Open Source Intelligence (OSINT) plays a large part of being a cybersecuity analyst. These various sites have the ability to paint a picture to help determine if artifacts like IP/URL/Hash values etc. have a known malicious/good reputation. 

When using OSINT, it is a good idea to check multiple sources. Because of this, I decided to write a program in python I am calling the OSINT Aggregator and wanted to show what I’ve done so far. I will post as I continue to build it.

When running this program, a gui will display and ask the user to choose between IP, URL, or Hash Value. After choosing, the user will input their artifact in question. My program will reach out to multiple OSINT APIs (VirusTotal, AlienVault OTX, IBM X-Force, abuseIPDB, geoIP for geolocation, and urlscan for a screenshot of landing page if the artifact is a URL). It returns JSON data from these APIs, formats it into a nice, readable report, and outputs it to the gui.

I am open to any comments or suggestions on how I can make this better. Thank you for reading. Here is a short video to show how it works (sorry for the screen recorded quality)
