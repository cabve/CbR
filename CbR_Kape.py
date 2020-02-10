## ----------------------------------------------------------------------------------------------------------------------------------------
## CbR KAPE Pull Script
## ----------------------------------------------------------------------------------------------------------------------------------------

import time
from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI(url="x", token="x", ssl_verify=False)

script_path = r'path'  # Where is local Kape.ps1 script?

#print('Enter Sensor ID:')
#sensor_id = raw_input()
sensor_id = x  # Use this to define the sensor ID in the script, rather than using input

try:
    sensor = c.select(Sensor, sensor_id)
    print('[INFO] Establishing session to CB Sensor #' + str(sensor.id) + '(' + sensor.hostname + ')')
    session = c.live_response.request_session(sensor.id)
    print('[SUCCESS] Connected on Session #' + str(session.session_id))
    
    try: session.create_directory('C:\Windows\CarbonBlack\Tools')
    except Exception: pass  # Existed already

    try: session.put_file(open(script_path + '\Kape.zip', 'rb'), 'C:\Windows\CarbonBlack\Tools\Kape.zip')
    except Exception:
        session.delete_file(r'C:\Windows\CarbonBlack\Tools\Kape.zip')
        session.put_file(open(script_path + '\Kape.zip', 'rb'), 'C:\Windows\CarbonBlack\Tools\Kape.zip')

    try: session.put_file(open(script_path + '\Kape.ps1', 'rb'), 'C:\Windows\CarbonBlack\Tools\Kape.ps1')
    except Exception:
        session.delete_file(r'C:\Windows\CarbonBlack\Tools\Kape.ps1')
        session.put_file(open(script_path + '\Kape.ps1', 'rb'), 'C:\Windows\CarbonBlack\Tools\Kape.ps1')
    
    session.create_process(r'''powershell.exe -ep Bypass -File "C:\Windows\CarbonBlack\Tools\Kape.ps1"''', True, None, None, 3600, True)
   
    print('[SUCCESS] Script execution successful. Navigate to destination location for artifacts.')
        
    session.get_file(r"C:\temp\KFF.zip")

    session.delete_file(r"C:\temp\KFF.zip")
    
except Exception as err:  # Catch potential errors
    print('[ERROR] Encountered: ' + str(err) + '\n[FAILURE] Fatal error caused exit!')  # Report error    

session.close()
print("[INFO] Session has been closed to CB Sensor #" + str(sensor.id))
print("[INFO] Script completed.")
