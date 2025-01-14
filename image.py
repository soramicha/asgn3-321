import sys

def processImage(image):
    with open(image, 'rb') as f:
        header = f.read(max(54, 138))
    return header[:54]





if __name__ == '__main__':
   processImage(sys.argv[1])