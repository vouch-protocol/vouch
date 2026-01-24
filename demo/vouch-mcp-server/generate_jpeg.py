from PIL import Image
import io

def generate_jpeg(filename="test.jpg"):
    # Create a new RGB image with Vouch brand color (approx)
    img = Image.new('RGB', (100, 100), color = (0, 0, 0)) # Black background
    img.save(filename)
    print(f"Generated valid JPEG: {filename}")

if __name__ == "__main__":
    generate_jpeg("/home/rampy/vouch-protocol/demo/vouch-mcp-server/test.jpg")
