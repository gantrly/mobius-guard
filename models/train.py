import pandas as pd
from datasets import Dataset
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification, 
    TrainingArguments, 
    Trainer
)
import evaluate
import numpy as np
import torch
import os

def main():
    print("🚀 Starting Stage 2: Model Fine-Tuning Pipeline...")
    
    # 1. Load the dataset generated in Stage 1
    df = pd.read_parquet("data/adversarial_dataset.parquet")
    
    # [DEV MODE]: If you want to test this quickly in Codespaces without waiting hours, 
    # uncomment the line below to train on just 100 rows. 
    df = df.sample(100) 
    
    dataset = Dataset.from_pandas(df)
    
    # Split into 80% Train, 20% Validation
    dataset = dataset.train_test_split(test_size=0.2, seed=42)
    
    # 2. Load Tokenizer & Model
    model_id = "microsoft/deberta-v3-small"
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    
    def tokenize_function(examples):
        # Truncate long inputs and pad short ones to exactly 128 tokens for speed
        return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=128)
        
    tokenized_datasets = dataset.map(tokenize_function, batched=True)
    
    # Load model with a binary classification head
    model = AutoModelForSequenceClassification.from_pretrained(
        model_id, 
        num_labels=2,
        id2label={0: "SAFE", 1: "INJECTION"},
        label2id={"SAFE": 0, "INJECTION": 1}
    )
    
    # 3. Define Evaluation Metrics (Accuracy & F1)
    accuracy = evaluate.load("accuracy")
    f1 = evaluate.load("f1")
    
    def compute_metrics(eval_pred):
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)
        acc = accuracy.compute(predictions=predictions, references=labels)
        f1_score = f1.compute(predictions=predictions, references=labels)
        return {**acc, **f1_score}

    # 4. Hardware-Aware Training Arguments
    # Automatically detects if you are on the AWS g6.xlarge (GPU) or Codespaces (CPU)
    has_gpu = torch.cuda.is_available()
    
    training_args = TrainingArguments(
        output_dir="./checkpoints",
        learning_rate=2e-5,
        per_device_train_batch_size=32 if has_gpu else 8,
        per_device_eval_batch_size=64 if has_gpu else 8,
        num_train_epochs=3,
        weight_decay=0.01,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        fp16=has_gpu,            # Uses Mixed Precision on GPU for 2x speed boost
        logging_steps=50,
        report_to="none"         # Disable external loggers for local runs
    )
    
    # 5. Initialize Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        tokenizer=tokenizer,
        compute_metrics=compute_metrics,
    )
    
    # 6. Train & Save
    print(f"🔥 Starting Training (Hardware Acceleration: {'Enabled (GPU)' if has_gpu else 'Disabled (CPU)'})...")
    trainer.train()
    
    print("💾 Saving best model to ./guardrail_model_final ...")
    trainer.save_model("./guardrail_model_final")
    tokenizer.save_pretrained("./guardrail_model_final")
    print("✅ Training Complete!")

if __name__ == "__main__":
    main()