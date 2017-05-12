from threading import Thread
import time

class Worker(Thread):
    def __init__(self,name):
        Thread.__init__(self)
        self.name= name
        print(self.name,': init')
        
    def run(self):
        while True:
            print(self.name,' awake')
            time.sleep(1)

if __name__ == '__main__':
    for x in range(4):
        worker= Worker('worker{}'.format(x))
        worker.daemon= True
        worker.start()
        
    while True:
        print('main awake')
        time.sleep(5)
        
    pass
    