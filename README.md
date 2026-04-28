# ZATCA Phase 2 Integration

A comprehensive Frappe/ERPNext module for integrating ZATCA (Zakat, Tax, and Customs Authority) Phase 2 E-Invoicing compliance into your business operations.

## 📋 Overview

This project provides a complete integration solution for ZATCA Phase 2 E-Invoicing requirements in the Kingdom of Saudi Arabia. It includes configuration management, invoice processing, validation, and submission capabilities through both the Frappe framework and the official ZATCA Java SDK.

**Project Name:** Zatca Amaken  
**Version:** 0.0.1  
**License:** MIT

## ✨ Features

- **ZATCA Settings Management** - Configure your organization's ZATCA compliance settings
- **Invoice Counting Settings** - Manage invoice number sequences and counting mechanisms
- **Sales Invoice Additional Fields** - Extend sales invoices with ZATCA-specific requirements
- **ZATCA Integration Logging** - Track all ZATCA API interactions and transactions
- **ZATCA Dashboard** - Visual overview of compliance status and invoice statistics
- **E-Invoice Validation** - Validate invoices against ZATCA requirements
- **Invoice Signing** - Digitally sign invoices for submission
- **QR Code Generation** - Generate compliance QR codes for invoices
- **Certificate Management** - Handle CSR and certificate signing requests
- **Testing Environment Support** - Dedicated testing settings for development

## 🏗️ Project Structure

```
ZATCA-Phase-2-Integration/
├── zatca_amaken/                          # Main Frappe module
│   ├── zatca_amaken/                      # Package source code
│   │   ├── doctype/                       # Custom document types
│   │   │   ├── zatca_amaken_settings/     # Main ZATCA configuration
│   │   │   ├── zatca_invoice_counting_settings/
│   │   │   ├── sales_invoice_additional_fields/
│   │   │   ├── zatca_integration_log/
│   │   │   └── zatca_settings_for_tseting/
│   │   ├── page/                          # Custom pages
│   │   │   └── zatca_dashboard/           # ZATCA dashboard interface
│   │   ├── dashboard_chart/               # Chart visualizations
│   │   ├── dashboard_chart_source/        # Chart data sources
│   │   ├── report/                        # Custom reports
│   │   └── workspace/                     # Custom workspace
│   ├── hooks.py                           # Frappe hooks configuration
│   ├── __init__.py
│   └── modules.txt
├── zatca-einvoicing-sdk-Java-238-R3.4.3/  # Official ZATCA Java SDK
│   ├── Apps/                              # Applications and utilities
│   ├── Configuration/                     # Configuration files
│   ├── Data/                              # Sample data and documentation
│   ├── install.bat                        # Windows installation script
│   ├── install.sh                         # Linux installation script
│   └── Readme/                            # SDK documentation
├── setup.py                               # Python package setup
├── requirements.txt                       # Python dependencies
├── MANIFEST.in                            # Package manifest
└── README.md                              # This file
```

## 🚀 Installation

### Prerequisites

- **Frappe Framework** - Installation via `bench init` (see requirements.txt)
- **Java Runtime** - Version 11 to 15 (required for ZATCA SDK)
- **Python** 3.8+
- **jq** (for Linux installations)

### Setup Steps

1. **Install the Frappe Module**

   ```bash
   # Navigate to your bench apps directory
   cd /path/to/bench/apps
   
   # Clone the repository
   git clone https://github.com/ahmed858/ZATCA-Phase-2-Integration.git
   
   # Install in your Frappe bench
   bench install-app zatca_amaken
   ```

2. **Install ZATCA SDK (Windows)**

   ```bash
   # Navigate to the SDK directory
   cd zatca_amaken/zatca-einvoicing-sdk-Java-238-R3.4.3
   
   # Run the installation script
   install.bat
   
   # Verify installation
   fatoora -help
   ```

3. **Install ZATCA SDK (Linux)**

   ```bash
   # Install jq first (if not already installed)
   # For Ubuntu/Debian:
   sudo apt-get install jq
   # For CentOS/RHEL:
   sudo yum install jq
   
   # Navigate to the SDK directory
   cd zatca_amaken/zatca-einvoicing-sdk-Java-238-R3.4.3
   
   # Run the installation script
   bash install.sh
   
   # Reload bash profile
   source ~/.bash_profile
   
   # Verify installation
   fatoora -help
   ```

4. **Configure ZATCA Settings in Frappe**

   - Navigate to **Zatca Amaken Settings** in your ERPNext instance
   - Fill in your organization's ZATCA credentials and configuration
   - Set up Invoice Counting Settings for invoice numbering
   - (Optional) Configure Testing Settings for development environment

## ⚙️ Configuration

### ZATCA Amaken Settings

Access **Zatca Amaken Settings** to configure:

- **Organization Information** - Company name, registration details
- **API Credentials** - ZATCA API endpoints and authentication tokens
- **Certificate Information** - Digital certificate paths and passphrases
- **Compliance Mode** - Production or testing environment

### Invoice Counting Settings

Configure invoice number sequences:

- Define sequential number ranges for different invoice types
- Set up automatic numbering patterns
- Track invoice count for compliance reporting

### Sales Invoice Additional Fields

Extend standard sales invoices with:

- ZATCA-specific line item fields
- Compliance status tracking
- Submission status indicators

## 📊 Dashboard & Reporting

The **ZATCA Dashboard** provides:

- Real-time compliance status overview
- Invoice submission statistics
- Integration error tracking
- Validation results summary

## 🔧 ZATCA Java SDK Commands

The included ZATCA SDK supports the following operations:

### Certificate & Key Management

```bash
# Generate Certificate Signing Request (CSR)
fatoora -csr -csrConfig config.json -privateKey private.key -generatedCsr csr.csr

# Generate CSR in PEM format
fatoora -csr -pem -csrConfig config.json -privateKey private.key -generatedCsr csr.pem
```

### Invoice Operations

```bash
# Validate invoice
fatoora -validate -invoice invoice.json

# Sign invoice
fatoora -sign -invoice invoice.json -signedInvoice signed_invoice.json

# Generate invoice hash
fatoora -generateHash -invoice invoice.json

# Generate API request
fatoora -invoiceRequest -invoice invoice.json -apiRequest request.json

# Generate QR code
fatoora -qr -invoice invoice.json
```

## 📝 Document Types

### Zatca Amaken Settings
Main configuration document for ZATCA integration settings and credentials.

### Zatca Invoice Counting Settings
Manages invoice number sequences and counting mechanisms for compliance.

### Sales Invoice Additional Fields
Custom fields extension for sales invoices to support ZATCA requirements.

### Zatca Integration Log
Audit trail of all ZATCA API interactions and transactions.

### Zatca Settings for Testing
Separate configuration document for development and testing environments.

## 🔄 Integration Flow

```
Sales Invoice Creation
    ↓
Validate against ZATCA Requirements
    ↓
Sign Invoice (using private key)
    ↓
Generate QR Code
    ↓
Submit to ZATCA API
    ↓
Log Integration Response
    ↓
Update Invoice Status
```

## 🧪 Testing

To test ZATCA integration:

1. Configure **Zatca Settings for Testing** with test environment credentials
2. Create test invoices with sample data
3. Use the validation tools to verify compliance
4. Review integration logs for any errors

## 📚 Documentation

- **ZATCA Official Documentation:** Refer to the `zatca-einvoicing-sdk-Java-238-R3.4.3/Readme/readme.md` file for detailed SDK documentation
- **SDK Configuration:** See `Configuration/` directory for sample configuration files
- **Sample Data:** Example invoices available in `Data/` directory

## 🔐 Security Considerations

- Store API credentials securely in the ZATCA settings
- Protect private keys with strong passphrases
- Use production certificates only in production environment
- Regularly audit integration logs for suspicious activity
- Enable two-factor authentication on ZATCA accounts

## 🐛 Troubleshooting

### Java Not Found Error
Ensure Java 11-15 is installed and in your system PATH:
```bash
java -version
```

### SDK Commands Not Found
Verify SDK installation path and environment variables:
```bash
# Windows
echo %FATOORA_HOME%

# Linux/Mac
echo $FATOORA_HOME
```

### Certificate Issues
- Verify certificate validity date and format
- Ensure private key matches the certificate
- Check certificate paths in ZATCA settings

## 🤝 Contributing

Contributions are welcome! Please follow standard Git workflow:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📞 Support

For issues, questions, or feedback:

- **Author:** Ahmed
- **Email:** hd
- **Repository Issues:** https://github.com/ahmed858/ZATCA-Phase-2-Integration/issues

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📖 Additional Resources

- [Frappe Framework Documentation](https://frappeframework.com)
- [ERPNext Documentation](https://docs.erpnext.com)
- [ZATCA Official Website](https://zatca.gov.sa)
- [E-Invoicing Specifications](https://zatca.gov.sa/en/E-Invoicing/GeneralSetting/Pages/default.aspx)

## 🔄 Version History

- **v0.0.1** - Initial release with ZATCA Phase 2 integration features

---

**Last Updated:** 2025  
**Status:** Active Development
