import json
from matplotlib import pyplot as plt

def weather_hist():
    with open('data/weather.json', 'r') as file:
        data = json.loads(file.read())['hourly']['data']
    
    items = ['temperature', 'humidity', 'windSpeed', 'cloudCover', 'ozone']
    
    for item in items:
        x = [value[item] for value in data]
        print(*x, sep = ', ')
        plt.hist(x, alpha = 0.5)
        plt.ylabel('Value')
        plt.title(item)
        plt.savefig('images/' + item + '.png')
        plt.clf()

def password_hist():
    with open('data/passwords.json', 'r') as file:
        data = json.loads(file.read())
    
    x = []
    
    for password in data:
        key = password.encode('ascii').hex()[0]
        for i in range(8):
            if int(key) & (2 ** i):
                x.append(i + 1)
    
    bins = [num + 0.5 for num in range(4)]
    plt.hist(x, bins = bins, alpha = 0.5)
    plt.ylabel('Value')
    plt.title('passwordBits')
    plt.savefig('images/passwords.png')
    plt.clf()

def key_hist(mode):
    x = []
    
    with open('data/' + mode + '_keys.txt', 'r') as file:
        for line in file.readlines():
            for i in range(8):
                if int(line[0] + line[1], 16) & (2 ** i):
                    x.append(i + 1)
    
    bins = [num + 0.5 for num in range(9)]
    plt.hist(x, bins = bins, alpha = 0.5)
    plt.ylabel('Value')
    plt.title('keyBits')
    plt.savefig('images/' + mode + '_keys.png')
    plt.clf()

if __name__ == '__main__':
    weather_hist()
    password_hist()
    
    key_hist('hkdf')
    key_hist('pbkdf2')