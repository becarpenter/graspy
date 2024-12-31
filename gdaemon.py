"""Start a silent GRASP daemon"""
import grasp
import time
grasp.skip_dialogue()
grasp._initialise_grasp()
while True:
    time.sleep(60)
