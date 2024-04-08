python -m pip install --upgrade --user -r requirements.txt
python -m pip install --upgrade --user pyinstaller
pyinstaller.exe  --onefile  convert_config.py 
