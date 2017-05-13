# -*- coding: utf-8 -*-
import re, urlparse, csv, requests, json, sys
from os import mkdir, remove, path, listdir
from time import time, asctime, sleep
import string

WEB_URL_REGEX = r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|
coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|
bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|
dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|
ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|
md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|
pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|
th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\
[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};
:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|
mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi
bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|
eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|
in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|
mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|
py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|
to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))"""

def strings(filename, min=4):
    with open(filename, "rb") as f:
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result

def convert_to_url(url):
    if url.startswith('http://www.'):
        return 'http://' + url[len('http://www.'):]
    if url.startswith('www.'):
        return 'http://' + url[len('www.'):]
    if not url.startswith('http://'):
        return 'http://' + url
    return url

def submit_vt(apikey, url):
    params = {'apikey': apikey, 'url': url}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
    return response.json()

def get_vt(apikey, url, scan_id=""):
    if scan_id:
        params = {'apikey': apikey, 'resource': url, 'scan_id': scan_id}
    else:
        params = {'apikey': apikey, 'resource': url}
    response = requests.post('http://www.virustotal.com/vtapi/v2/url/report', data=params)
    return response.json()

def main():
    try:
        try:
            scan_path = sys.argv[1]
        except IndexError:
                scan_path = 'scan/'
        try:
            api_key = sys.argv[2]
        except IndexError:
            api_key = 'YOUR_API_KEY'
        csv_url = "csv_url.csv"
        csv_submit_response = 'submit_result.csv'
        csv_get_response = 'get_report_result.csv'
        sleep_time = 25 # sleep time before we submit new url in virustotal (in 25 seconds)
        debug = True # turn it of if you dont want noise...
        submit_result = True
        get_result = True
        use_scan_id = False # If it's set to true, we are using scan_id to get spesific report with scan id that we had
        this_time = str(asctime()).replace(":", "-")
        if debug:
            print "[*] Data will be saved on directory -> %s" % this_time
        # print this_time
        mkdir(path.normpath(this_time))
        clean_time = str(time())
        try:
            csvfile = open(this_time+"/"+csv_url, 'wb')
        except IOError:
            print "[*] Please close data.csv first."
            sys.exit(1)

        url_list = []

        spamwriter = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL, delimiter=",")
        spamwriter.writerow(["Url", "Fromfile"])

        '''Gather url from file in directory'''
        for filename in listdir(scan_path):
            with open(scan_path+filename, mode='rb') as file: # so we have script that only can scan text file, with binary apps
                for s in strings(scan_path+filename):
                    try:
                        # less than 10 charachter, it was marked as url, but actually its a garbage data
                        if len(s) > 10:
                            # find url pattern and
                            urlres = re.findall(WEB_URL_REGEX, s)[0]
                            # and convert it to proper url if not
                            if "http" not in urlres:
                                urlres = convert_to_url(urlres)
                            # Check we are not having repeated url on list'''
                            if urlres not in url_list:
                                url_list.append(urlres)
                                # saving to csv
                                spamwriter.writerow([urlres, scan_path+filename])
                                if debug:
                                    print "[*] Url Found %s at %s " % (urlres, scan_path+filename)
                    except IndexError:
                        pass

        # close file
        csvfile.close()
        file.close()

        '''Submit url to virus total'''
        if get_result and submit_result:
            response_result_list = []
            '''Prepare file for response result csv data'''
            with open(this_time+"/"+csv_submit_response, 'wb') as csvfile_submit:
                spamwriter = csv.writer(csvfile_submit, quoting=csv.QUOTE_MINIMAL, delimiter=",")
                spamwriter.writerow(["response_code", "verbose_msg", "scan_id", "scan_date", "url", "permalink"])
                for url in url_list:
                    # sleep first to make it always safe to send in every loop, we dont want bad things happen ;)
                    print "[*] Sleeping for %d seconds..." % (sleep_time)
                    sleep(sleep_time)
                    print "[*] Continuing..."
                    print "[*] Sending submission %s to virustotal.com" % (url)
                    result = submit_vt(api_key, url)
                    try:
                        #print result
                        if debug:
                            print json.dumps(result)
                        response_code = result["response_code"]
                        verbose_msg = str(result["verbose_msg"])
                        scan_id = str(result["scan_id"])
                        scan_date = str(result["scan_date"])
                        url = str(result["url"])
                        permalink = str(result["permalink"])
                        '''Save it to response result csv data'''
                        spamwriter.writerow([response_code, verbose_msg, scan_id, scan_date, url, permalink])
                        '''Add to list for later use...'''
                        response_result_list.append([response_code, verbose_msg, scan_id, scan_date, url, permalink])
                        #print repr(response_result_list)
                        print "[*] Sending submission %s to virustotal.com, successful!" % (url)
                    except (AttributeError, IndexError, KeyError, TypeError) as e:
                        print "[*] There was an error on response result. Error code : %s" % e
                        print "[*] Continuing..."
                        pass

            # close file
            csvfile_submit.close()

        if get_result:
            get_result_list = []
            '''Prepare file for response result csv data'''
            with open(this_time+"/"+csv_get_response, 'wb') as csvfile_get:
                spamwriter = csv.writer(csvfile_get, quoting=csv.QUOTE_MINIMAL, delimiter=",")
                spamwriter.writerow(
                    ["response_code", "verbose_msg", "scan_id", "permalink", "url", "scan_date", "filescan_id", "positives",
                     "total"])
                '''Get result from virus total'''
                for response in response_result_list:
                    print "[*] Getting report url %s from virustotal.com" % (response[4])
                    # sleep first to make it always safe to send in every loop, we dont want bad things happen ;)
                    print "[*] Sleeping for %d seconds..." % (sleep_time)
                    sleep(sleep_time)
                    print "[*] Continuing..."
                    if use_scan_id:
                        result = get_vt(api_key, response[4], response[2])
                    else:
                        result = get_vt(api_key, response[4])
                    #print result
                    try:
                        response_code = result["response_code"]
                        verbose_msg = str(result["verbose_msg"])
                        scan_id = str(result["scan_id"])
                        permalink = str(result["permalink"])
                        url = str(result["url"])
                        scan_date = str(result["scan_date"])
                        filescan_id = str(result["filescan_id"])
                        positives = str(result["positives"])
                        total = str(result["total"])
                        '''Save it to response result csv data'''
                        spamwriter.writerow([response_code, verbose_msg, scan_id, permalink, url, scan_date, filescan_id, positives, total])
                        '''Add to list for later use...'''
                        get_result_list.append([response_code, verbose_msg, scan_id, permalink, url, scan_date, filescan_id, positives, total])
                        print "[*] Getting report url %s from virustotal.com, sucessfull!" % (result['url'])
                    except (AttributeError, IndexError, KeyError, TypeError) as e:
                        print "[*] There was an error on response result. Error code : %s" % e
                        print "[*] Continuing..."
                        pass
            csvfile_get.close()

    except KeyboardInterrupt:
        print "\n[-] Aborting...\n"
        sys.exit(1)

if __name__ == '__main__':
    print "Virustotal Link Scanner by <yudha.gunslinger@gmail.com>"
    main()