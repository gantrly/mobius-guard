from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
from optimum.onnxruntime.configuration import AutoQuantizationConfig
from transformers import AutoTokenizer
import os

def main():
    print("🚀 Starting Stage 3: ONNX Export and INT8 Quantization...")
    
    # We are using the base model to wire up the Next.js proxy.
    # (After you train on AWS, you would change this to "./guardrail_model_final")
    model_id = "microsoft/deberta-v3-small"
    save_dir = "./onnx_model"
    
    print(f"1. Loading '{model_id}' and exporting PyTorch graph to ONNX...")
    # export=True forces the conversion from PyTorch to ONNX format
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = ORTModelForSequenceClassification.from_pretrained(model_id, export=True)
    
    # Save the unquantized model
    tokenizer.save_pretrained(save_dir)
    model.save_pretrained(save_dir)
    print("✅ Raw ONNX model exported.")

    print("2. Applying Dynamic INT8 Quantization (Optimizing for CPU speed)...")
    # This process shrinks the model size by ~70% and drastically speeds up CPU inference
    quantizer = ORTQuantizer.from_pretrained(save_dir)
    
    # avx2 configuration is highly optimized for standard CPUs (like in Codespaces or local Node.js)
    dqconfig = AutoQuantizationConfig.avx2(is_static=False, per_channel=False)
    
    quantizer.quantize(
        save_dir=save_dir,
        quantization_config=dqconfig,
    )
    
    print(f"✅ Quantization Complete! Your production-ready model is in the '{save_dir}' folder.")
    print("Look for the 'model_quantized.onnx' file - this is what Next.js will load!")

if __name__ == "__main__":
    main()