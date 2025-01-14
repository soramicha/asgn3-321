import sys

def processImage(image):
    # open the file in binary mode
    with open(image, 'rb') as f:
        # read the file and the header up
        header = f.read(max(54, 138))
    # return the standardd 54 byte headerdef
    return header[:54]

def generateKey():
    # generate random key if not provided
    print("todo")
    
def generateIV():
    # generate random IV if not provided
    print("todo")

def main():
    img_header = processImage(sys.argv[1])
    
    # ECB
    generateKey()
    
    # CBC
    generateIV()

if __name__ == '__main__':
   main()