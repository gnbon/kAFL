f = open("./in/seed_000", "w")
data = '\x00'+'A'*0xff
f.write(data)
f.close()
