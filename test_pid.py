import subprocess
import time
import docker

def run():
    print("Testing create() then start()...")
    client = docker.from_env()
    container = client.containers.create(
        image='debian:stable-slim',
        command='sleep 10',
        detach=True,
        tty=True
    )
    print(f"Container ID: {container.id}")
    
    container.start()
    
    time.sleep(1)
    
    container.reload()
    print(f"docker-py State.Pid: {container.attrs['State']['Pid']}")
    
    ps_output = subprocess.check_output(["ps", "-ef"]).decode()
    for line in ps_output.split('\n'):
        if str(container.attrs['State']['Pid']) in line or "sleep 10" in line:
            print(line)
            
    container.remove(force=True)

run()
