import sys
import json
from transformers import BlipProcessor, BlipForConditionalGeneration
from PIL import Image

# Load BLIP model (image captioning)
processor = BlipProcessor.from_pretrained("Salesforce/blip-image-captioning-base")
model = BlipForConditionalGeneration.from_pretrained("Salesforce/blip-image-captioning-base")

def generate_caption(image_path):
    image = Image.open(image_path).convert("RGB")
    inputs = processor(image, return_tensors="pt")
    out = model.generate(**inputs, max_length=30)
    caption = processor.decode(out[0], skip_special_tokens=True)
    return caption

if __name__ == "__main__":
    image_path = sys.argv[1]
    caption = generate_caption(image_path)
    print(json.dumps({"caption": caption}))
