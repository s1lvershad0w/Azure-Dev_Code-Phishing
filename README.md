# ADC_Enum.ps1

This is a POC script to automate the information gathering phase during an Azure Device Code Phishing attack. For more information refer the blogpost: https://www.offsec-journey.com/post/phishing-with-azure-device-codes

**Step To Run**
1. Copy ADCEnum.ps1 to TokenTactics directory
2. Install-Module AzureAD
3. Ensure script is updated with victim EMAIL & DEVICE_CODE
4. Save console output to file) by running the command: Start-Transcript -Path C:\Temp\ 
5. EXECUTE SCRIPT: .\ADCEnum.ps1
6. Stop-Transcript

# Credits
* Dr Nestori Syynimaa's Blog
* @0xBoku - The Art of the Device Code Phish
* @Mr-Un1k0d3r - GitHub 
* @rvrsh3ll - TokenTactics 
* Microsoft - OAuth Device Auth Flow 
