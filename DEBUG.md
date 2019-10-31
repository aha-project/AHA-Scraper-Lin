## Levels  
- 0:  
- 1:  
- 2:  
- 3:  
- 4: 
- 5: 

## Debug Recalls  
To allow debug recall to work `os.popen` lines must not be changed in order or in run times.
Adding more will still allow it to work fine but extra `os.popen`s will be blank. Try to keep the conditional
the same between fixes and feature upgrades.  

Use `-o` or `-i` to use debug recalls. 

## Debug Version Compatibility  
| **Version** | **Commit Hash** |
| :--- | --- |
| 19.8.2 | 5248d52 |  

