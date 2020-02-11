## ----------------------------------------------------------------------------------------------------------------------------------------
## CbR KAPE Pull Script
## ----------------------------------------------------------------------------------------------------------------------------------------
import time
import requests
from cbapi.response import CbEnterpriseResponseAPI, Sensor

ApiToken = "apikey"
c = CbEnterpriseResponseAPI(url="url", token=ApiToken, ssl_verify=False)

script_path = r'x:\scriptpath'  # Where is local Kape.ps1 script?

print('Enter Sensor ID:')
sensor_id = input()
session_id = ""

try:
    # Connect to CbR and establish live response session
    sensor = c.select(Sensor, sensor_id)
    print('[INFO] Establishing session to CB Sensor #' + str(sensor.id) + '(' + sensor.hostname + ')')

    session = c.live_response.request_session(sensor.id)
    print('[SUCCESS] Connected on Session #' + str(session.session_id))
    session_id = session.session_id
    
    try: session.create_directory('C:\Windows\CarbonBlack\Tools')
    except Exception: pass  # Existed already

    # Transfer scripts to live response host
    print('[INFO] Transfering script files to CB Sensor #' + sensor_id)
    try: session.put_file(open(script_path + '\Kape.zip', 'rb'), 'C:\Windows\CarbonBlack\Tools\Kape.zip')
    except Exception:
        session.delete_file(r'C:\Windows\CarbonBlack\Tools\Kape.zip')
        session.put_file(open(script_path + '\Kape.zip', 'rb'), 'C:\Windows\CarbonBlack\Tools\Kape.zip')

    try: session.put_file(open(script_path + '\Kape.ps1', 'rb'), 'C:\Windows\CarbonBlack\Tools\Kape.ps1')
    except Exception:
        session.delete_file(r'C:\Windows\CarbonBlack\Tools\Kape.ps1')
        session.put_file(open(script_path + '\Kape.ps1', 'rb'), 'C:\Windows\CarbonBlack\Tools\Kape.ps1')
    
    # Execute script on live response host
    print('[INFO] Starting data collection)
    session.create_process(r'''powershell.exe -ep Bypass -File "C:\Windows\CarbonBlack\Tools\Kape.ps1"''', True, None, None, 3600, True)
   
    print('[SUCCESS] Script execution successful. Navigate to destination location for artifacts.')
    
    # Transfer data from live response host to CbR Mastersrv
    print('[INFO] Transfering data to CbR Master')
    session.get_file(r"C:\temp\KFF.zip")

    # Clean up on live response host
    print('[INFO] Cleaning up on CB Sensor #' + sensor_id)
    session.delete_file(r"C:\temp\KFF.zip")
    
except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error    

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id))

print("[INFO] Starting download of collected data")

# Open session to CbR Mastersrv and download file extracted file
headers = {'User-Agent': 'Mozilla/5.0 CbR API',
		   'X-Auth-Token': ApiToken
           }
           
# file id could be different
r = requests.get("cbrurl/api/v1/cblr/session/"+str(session_id)+"/file/6/content",headers=headers, verify=False)

if r.status_code == 200:
	zname="C:\\temp\\KFF.zip"
	zfile=open(zname, 'wb')
    print("[INFO] File downloaded correctly. Saving file to C:\temp\KFF.zip.") 
	zfile.write(r.content)
	zfile.close()
    
print("[INFO] Script completed.")
