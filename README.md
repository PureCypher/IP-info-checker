# IP Information Fetcher Application

## Overview
This application is a graphical user interface (GUI) tool built using PyQt6 that allows users to fetch and display information about an IP address from three different sources:
- **IPinfo.io**: General information about the IP.
- **AbuseIPDB**: Abuse confidence score, reports, and other abuse-related data.
- **ip-api.com**: Geolocation details and ISP information.

## Features
- Validate IPv4 and IPv6 addresses.
- Fetch detailed information from multiple APIs.
- Display fetched data in a user-friendly tabbed interface.
- Threaded network requests to avoid freezing the GUI.

## Prerequisites
- Python 3.8 or higher.
- install requirements ('pip install -r requirements.txt')

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/PureCypher/IP-info-checker.git
   cd IP-info-checker

2. **Install Required Libraries**
   ```bash
   pip install -r requirements.txt
   ```

   Alternatively, you can manually install the required libraries:
   ```bash
   pip install PyQt6 requests ipaddress
   ```

## Usage
1. **Run the Application**:
   ```bash
   python app.py
   ```

2. **Enter an IP Address**:
   - Enter a valid IPv4 or IPv6 address in the input field.
   - Click the "Fetch Information" button.

3. **View Results**:
   - The fetched information will be displayed in three tabs: IPinfo, AbuseIPDB, and ip-api.com.

## Configuration
- **API Keys**: If required by any of the APIs in the future, you can configure them in the `app.py` file or through environment variables.
  ```
  Line 25 change PUTAPIKEYHERE to your AbuseIPDB API token
  Line 48 change PUTTOKENHERE to your IPInfo API token
  ```
