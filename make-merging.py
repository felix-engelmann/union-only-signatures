from glob import glob
import json

for m in ["merging","merging10","merging100","merging1000","unsorted1000"]:
    for f in glob("target/criterion/"+m+"/*"):
        try:
            x=int(f.split("/")[-1])
        except:
            continue
        #print(f,x)
        with open(f+"/new/estimates.json") as fd:
            data = json.load(fd)
        #print(data)
        print(f"({x},{data['mean']['point_estimate']/1000}) +- (0,{data['std_dev']['point_estimate']/1000})")
    print("\\addlegendentry{"+m+"};")
