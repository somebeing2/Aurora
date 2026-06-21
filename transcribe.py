import os
import argparse

def transcribe_with_openai_whisper(model_size, audio_path):
    import whisper
    
    model = whisper.load_model(model_size)
    result = model.transcribe(audio_path)
    
    language = result.get("language", "unknown")
    text = result["text"]
    
    return language, text


def transcribe_with_faster_whisper(model_size, audio_path):
    from faster_whisper import WhisperModel
    
    model = WhisperModel(model_size, compute_type="int8")
    segments, info = model.transcribe(audio_path)
    
    text = ""
    for segment in segments:
        text += segment.text + " "
    
    return info.language, text.strip()


def main():
    parser = argparse.ArgumentParser(description="Transcribe WAV files")
    parser.add_argument("--engine", choices=["openai", "faster"], required=True,
                        help="Choose transcription engine")
    parser.add_argument("--model", default="small",
                        help="Model size: tiny, base, small, medium, large")
    
    args = parser.parse_args()
    
    audio_folder = "audiofiles"
    output_folder = "transcripts"
    
    os.makedirs(output_folder, exist_ok=True)

    wav_files = [f for f in os.listdir(audio_folder) if f.endswith(".wav")]

    if not wav_files:
        print("No WAV files found in audiofiles/")
        return

    print(f"Found {len(wav_files)} files")

    for file in wav_files:
        file_path = os.path.join(audio_folder, file)
        print(f"\nProcessing: {file}")

        if args.engine == "openai":
            language, text = transcribe_with_openai_whisper(args.model, file_path)
        else:
            language, text = transcribe_with_faster_whisper(args.model, file_path)

        print(f"Detected language: {language}")
        print(f"Transcription: {text}")

        output_file = os.path.join(output_folder, file.replace(".wav", ".txt"))

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Detected Language: {language}\n\n")
            f.write(text)

        print(f"Saved to: {output_file}")

    print("\nAll files processed.")


if __name__ == "__main__":
    main()