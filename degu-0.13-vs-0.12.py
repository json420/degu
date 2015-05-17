#!/usr/bin/python3

"""
Benchmarking was done on an Intel i7-4900MQ (System76 Kudu Professional).

Do do the same yourself:

    bzr checkout lp:degu
    cd degu
    ./setup.py build_ext -i
    ./benchmark.py --runs=50 --requests=50000
    ./benchmark.py --runs=50 --requests=50000 --unix

These easiest way to get the build dependencies on Ubuntu:

    sudo add-apt-repository lp:novacut/stable
    sudo apt-get update
    sudo apt-get build-dep degu

After which you might as well install Degu from the PPA:

    sudo apt-get install python3-degu
"""

inet6 = [
    {
        "Degu": "0.13.0",
        "Python": "3.4.3, x86_64, Linux (Ubuntu 15.04)",
        "average": 53369.644597407685,
        "family": "AF_INET6",
        "fastest": 64232.57602438168,
        "requests": 50000,
        "runs": 50,
        "slowest": 46191.119289009985,
        "stdev": 3093.51078841401
    },
    {
        "Degu": "0.12.0",
        "Python": "3.4.3, x86_64, Linux (Ubuntu 15.04)",
        "average": 24423.53066426886,
        "family": "AF_INET6",
        "fastest": 25470.86644667456,
        "requests": 50000,
        "runs": 50,
        "slowest": 20941.78035161178,
        "stdev": 1261.2875855776608
    }
]

unix = [ 
    {
        "Degu": "0.13.0",
        "Python": "3.4.3, x86_64, Linux (Ubuntu 15.04)",
        "average": 76899.26269537566,
        "family": "AF_UNIX",
        "fastest": 91072.74415924549,
        "requests": 50000,
        "runs": 50,
        "slowest": 72727.91506073772,
        "stdev": 3474.5434550034242
    },
    {
        "Degu": "0.12.0",
        "Python": "3.4.3, x86_64, Linux (Ubuntu 15.04)",
        "average": 31903.37860541581,
        "family": "AF_UNIX",
        "fastest": 38277.01814769294,
        "requests": 50000,
        "runs": 50,
        "slowest": 27700.2374111583,
        "stdev": 1493.3328615104576
    }
]

def percent(a, b, key):
    f = a[key] / b[key]
    return int(f * 100 - 100)

for (a, b) in [inet6, unix]:
    assert a['family'] == b['family']
    assert a['requests'] == b['requests']
    assert a['runs'] == b['runs']
    print(a['family'])
    for key in ('average', 'fastest'):
        print('{}: {}%'.format(key, percent(a, b, key)))
    print('')     

