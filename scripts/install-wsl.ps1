# Run from Windows PowerShell with administrator privileges to install WSL only.
# The actual LocalPwn installer executes inside Kali Linux, not Windows.
Write-Host 'LocalPwn requires Kali Linux in a VM or WSL2. Run these only if WSL is not installed:'
Write-Host '  wsl --install -d kali-linux'
Write-Host 'Then launch Kali, clone the repo, and run: bash scripts/express-install.sh'
Write-Host 'Docker and VirtualBox are independent optional choices; neither is installed by this script.'
