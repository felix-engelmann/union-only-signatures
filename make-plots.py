from glob import glob
import json

for m in ["verifying","signing"]:
    for hashes in reversed([1,10,100,478]):
        mark="+"
        if m=="verifying":
            mark="o"
        print("\\addplot[only marks,mark="+mark+",error bars/.cd,y dir=both ,y explicit] coordinates {")
        for f in glob("target/criterion/"+m+"/s*-h"+str(hashes)):
            try:
                ps = f.split("/")[-1].split("-")
                size = int(ps[0][1:])
                #hashes = int(ps[1][1:])
                #print("size",size,"hashes",hashes)
            except:
                continue
            #print(f,x)
            with open(f+"/new/estimates.json") as fd:
                data = json.load(fd)
            #print(data)
            offset=""
            if m=="verifying":
                offset=".4"
            print(f"({size}{offset},{data['mean']['point_estimate']/1000000}) +- (0,{data['std_dev']['point_estimate']/1000000})")
        print("};")
        print("\\addlegendentry{"+m+" -- "+str(hashes)+" hashes};")
