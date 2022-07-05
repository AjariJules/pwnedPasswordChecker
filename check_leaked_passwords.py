import requests
import hashlib
import sys

PWNED_API_URL = 'https://api.pwnedpasswords.com/range/'
def password_check(list, password):
    for item in list:
        if item['hash'] == password:
            return(item)
    return(None)

def get_sha1_pass(password):    
    sha1_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1_pass

def get_pwnd_api_data(sha1_pass):
    first_five=  sha1_pass[0:5]
    url = f'{PWNED_API_URL}/{first_five[0:5]}' 
    try:
        res = requests.get(url)
        res.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
        exit()
                    
    results = res.content.decode("utf-8").split()
    suffixes_list = [dict(zip(['hash','count'], item.split(':'))) for item in results]
    full_hashed_list = [ {'hash': first_five + item['hash'] , 'count': item['count']} for item in suffixes_list]
    return  full_hashed_list           

    
def main():
    passwords = (sys.argv[1:])
    for password in passwords:
        hashed_pass = get_sha1_pass(password)
        pwnd_passwords = get_pwnd_api_data(hashed_pass)
        pass_check = password_check(pwnd_passwords,hashed_pass)

        if pass_check:
            print(f'Password {password} leaked { pass_check["count"] } times,  consider using a different password')
        else:
            print(f'Password {password} was never leaked, should be safe :) ')
            
if __name__ == '__main__':
    main()
    
    
    

    

        