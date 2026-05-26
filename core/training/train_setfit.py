import os
import sys
import json
import random
from datasets import Dataset
from setfit import SetFitModel, Trainer, TrainingArguments

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

def train():
    print("[+] Loading training dataset...")
    # Load dataset
    with open("data/training_dataset.json", "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    # Shuffle
    random.seed(42)
    random.shuffle(raw_data)

    # Split 80/20
    split_idx = int(len(raw_data) * 0.8)
    train_data = raw_data[:split_idx]
    eval_data = raw_data[split_idx:]

    print(f"Dataset Split: {len(train_data)} train examples, {len(eval_data)} evaluation examples.")

    # Convert to Hugging Face Dataset format
    train_dict = {"text": [x["text"] for x in train_data], "label": [x["label"] for x in train_data]}
    eval_dict = {"text": [x["text"] for x in eval_data], "label": [x["label"] for x in eval_data]}

    train_ds = Dataset.from_dict(train_dict)
    eval_ds = Dataset.from_dict(eval_dict)

    print("[+] Downloading base model: sentence-transformers/paraphrase-MiniLM-L6-v2 ...")
    # Load a lightweight, high-performance Sentence Transformer model for SetFit
    model = SetFitModel.from_pretrained("sentence-transformers/paraphrase-MiniLM-L6-v2")

    print("[+] Preparing training arguments...")
    # Few-shot SetFit training parameters
    args = TrainingArguments(
        batch_size=16,
        num_epochs=1,
        num_iterations=20, # SetFit contrastive pair generation iteration count
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=eval_ds
    )

    print("[+] Starting SetFit contrastive training loop (running on CPU)...")
    trainer.train()

    print("[+] Evaluating SetFit classifier performance on the test set...")
    metrics = trainer.evaluate()
    print("=" * 50)
    print(f"Accuracy Metrics: {metrics}")
    print("=" * 50)

    # Export model to persistent workspace folder
    os.makedirs("models", exist_ok=True)
    print("[+] Saving fine-tuned SetFit weights to 'models/setfit_input_guard'...")
    model.save_pretrained("models/setfit_input_guard")
    print("[+] Model successfully saved and ready for inference!")

if __name__ == "__main__":
    train()
