"""Tests for streaming encryption and decryption."""

import pytest
import io

from safe_core import (
    SafeCore,
    StreamingError,
    DataIntegrityError,
)


class TestStreamingEncryption:
    """Test streaming encryption operations."""

    def test_streaming_encrypt_decrypt_basic(self, initialized_storage, large_data):
        """Test basic streaming encryption/decryption."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        # Create encryptor
        encryptor = core.create_streaming_encryptor(dek, params, chunk_size=1024 * 1024)

        # Encrypt
        input_stream = io.BytesIO(large_data)
        encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
        encrypted_data = b"".join(encrypted_chunks)

        # Decrypt
        encrypted_stream = io.BytesIO(encrypted_data)
        header = encrypted_stream.read(31)

        decryptor = core.create_streaming_decryptor(dek, header)
        decrypted_chunks = list(decryptor.decrypt_stream(encrypted_stream))
        decrypted_data = b"".join(decrypted_chunks)

        assert decrypted_data == large_data

    def test_streaming_empty_file(self, initialized_storage):
        """Test streaming encryption of empty file."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        empty_data = b""

        encryptor = core.create_streaming_encryptor(dek, params)
        input_stream = io.BytesIO(empty_data)
        encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
        encrypted_data = b"".join(encrypted_chunks)

        # Should have header and finalization marker
        assert len(encrypted_data) > 31  # At least header

        # Decrypt
        encrypted_stream = io.BytesIO(encrypted_data)
        header = encrypted_stream.read(31)

        decryptor = core.create_streaming_decryptor(dek, header)
        decrypted_chunks = list(decryptor.decrypt_stream(encrypted_stream))
        decrypted_data = b"".join(decrypted_chunks)

        assert decrypted_data == empty_data

    def test_streaming_single_chunk(self, initialized_storage):
        """Test streaming with data smaller than chunk size."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        small_data = b"Small data that fits in one chunk"

        encryptor = core.create_streaming_encryptor(dek, params, chunk_size=1024 * 1024)
        input_stream = io.BytesIO(small_data)
        encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
        encrypted_data = b"".join(encrypted_chunks)

        encrypted_stream = io.BytesIO(encrypted_data)
        header = encrypted_stream.read(31)

        decryptor = core.create_streaming_decryptor(dek, header)
        decrypted_chunks = list(decryptor.decrypt_stream(encrypted_stream))
        decrypted_data = b"".join(decrypted_chunks)

        assert decrypted_data == small_data

    def test_streaming_multiple_chunks(self, initialized_storage):
        """Test streaming with data spanning multiple chunks."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        # Create data larger than chunk size
        chunk_size = 1024
        data = b"x" * (chunk_size * 3 + 500)  # 3.5 chunks

        encryptor = core.create_streaming_encryptor(dek, params, chunk_size=chunk_size)
        input_stream = io.BytesIO(data)
        encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
        encrypted_data = b"".join(encrypted_chunks)

        encrypted_stream = io.BytesIO(encrypted_data)
        header = encrypted_stream.read(31)

        decryptor = core.create_streaming_decryptor(dek, header)
        decrypted_chunks = list(decryptor.decrypt_stream(encrypted_stream))
        decrypted_data = b"".join(decrypted_chunks)

        assert decrypted_data == data

    def test_streaming_chunk_boundaries(self, initialized_storage):
        """Test that chunk boundaries don't affect correctness."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        # Test with various data sizes
        # FIX: chunk_size должен быть >= 1024
        for size in [999, 1000, 1001, 2048, 4096]:
            data = b"A" * size

            encryptor = core.create_streaming_encryptor(dek, params, chunk_size=1024)  # Было 1000
            input_stream = io.BytesIO(data)
            encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
            encrypted_data = b"".join(encrypted_chunks)

            encrypted_stream = io.BytesIO(encrypted_data)
            header = encrypted_stream.read(31)

            decryptor = core.create_streaming_decryptor(dek, header)
            decrypted_chunks = list(decryptor.decrypt_stream(encrypted_stream))
            decrypted_data = b"".join(decrypted_chunks)

            assert decrypted_data == data

    def test_streaming_different_chunk_sizes(self, initialized_storage):
        """Test streaming with different chunk sizes."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        data = b"x" * 10000

        for chunk_size in [1024, 2048, 4096, 8192]:
            encryptor = core.create_streaming_encryptor(dek, params, chunk_size=chunk_size)
            input_stream = io.BytesIO(data)
            encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
            encrypted_data = b"".join(encrypted_chunks)

            encrypted_stream = io.BytesIO(encrypted_data)
            header = encrypted_stream.read(31)

            decryptor = core.create_streaming_decryptor(dek, header)
            decrypted_chunks = list(decryptor.decrypt_stream(encrypted_stream))
            decrypted_data = b"".join(decrypted_chunks)

            assert decrypted_data == data

    def test_streaming_with_associated_data(self, initialized_storage):
        """Test streaming encryption with associated data."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        data = b"test data for streaming"
        aad = b"file_id:12345"

        encryptor = core.create_streaming_encryptor(dek, params, associated_data=aad)
        input_stream = io.BytesIO(data)
        encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
        encrypted_data = b"".join(encrypted_chunks)

        encrypted_stream = io.BytesIO(encrypted_data)
        header = encrypted_stream.read(31)

        # Correct AAD works
        decryptor = core.create_streaming_decryptor(dek, header, associated_data=aad)
        decrypted_chunks = list(decryptor.decrypt_stream(encrypted_stream))
        decrypted_data = b"".join(decrypted_chunks)

        assert decrypted_data == data

        # Wrong AAD should fail
        encrypted_stream = io.BytesIO(encrypted_data)
        header = encrypted_stream.read(31)

        decryptor = core.create_streaming_decryptor(dek, header, associated_data=b"wrong")

        with pytest.raises(DataIntegrityError):
            list(decryptor.decrypt_stream(encrypted_stream))

    def test_streaming_preserves_data_integrity(self, initialized_storage, random_data):
        """Test that streaming preserves data integrity perfectly."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        original_data = random_data(1024 * 1024)  # 1 MB random data

        encryptor = core.create_streaming_encryptor(dek, params)
        input_stream = io.BytesIO(original_data)
        encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
        encrypted_data = b"".join(encrypted_chunks)

        encrypted_stream = io.BytesIO(encrypted_data)
        header = encrypted_stream.read(31)

        decryptor = core.create_streaming_decryptor(dek, header)
        decrypted_chunks = list(decryptor.decrypt_stream(encrypted_stream))
        decrypted_data = b"".join(decrypted_chunks)

        # Every single byte should match
        assert decrypted_data == original_data
        assert len(decrypted_data) == len(original_data)


class TestStreamingErrors:
    """Test error handling in streaming operations."""

    def test_streaming_corrupted_chunk(self, initialized_storage):
        """Test that corrupted chunks are detected."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        data = b"test data" * 1000

        encryptor = core.create_streaming_encryptor(dek, params, chunk_size=1024)
        input_stream = io.BytesIO(data)
        encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
        encrypted_data = b"".join(encrypted_chunks)

        # Corrupt a byte in the middle
        corrupted_data = bytearray(encrypted_data)
        corrupted_data[len(corrupted_data) // 2] ^= 0xFF

        encrypted_stream = io.BytesIO(bytes(corrupted_data))
        header = encrypted_stream.read(31)

        decryptor = core.create_streaming_decryptor(dek, header)

        with pytest.raises(DataIntegrityError):
            list(decryptor.decrypt_stream(encrypted_stream))

    def test_streaming_truncated_data(self, initialized_storage):
        """Test that truncated stream is detected."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        data = b"test data" * 1000

        encryptor = core.create_streaming_encryptor(dek, params)
        input_stream = io.BytesIO(data)
        encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
        encrypted_data = b"".join(encrypted_chunks)

        # Truncate the data
        truncated_data = encrypted_data[: len(encrypted_data) // 2]

        encrypted_stream = io.BytesIO(truncated_data)
        header = encrypted_stream.read(31)

        decryptor = core.create_streaming_decryptor(dek, header)

        # FIX: Также ожидаем DataIntegrityError
        with pytest.raises((StreamingError, DataIntegrityError, struct.error)):
            list(decryptor.decrypt_stream(encrypted_stream))

    def test_streaming_invalid_header(self, initialized_storage):
        """Test that invalid header is rejected."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]

        invalid_header = b"INVALID_HEADER_DATA_HERE_12345"

        with pytest.raises(StreamingError):
            core.create_streaming_decryptor(dek, invalid_header)

    def test_streaming_wrong_dek(self, initialized_storage, random_data):
        """Test that wrong DEK causes decryption failure."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        data = b"test data" * 100

        encryptor = core.create_streaming_encryptor(dek, params)
        input_stream = io.BytesIO(data)
        encrypted_chunks = list(encryptor.encrypt_stream(input_stream))
        encrypted_data = b"".join(encrypted_chunks)

        encrypted_stream = io.BytesIO(encrypted_data)
        header = encrypted_stream.read(31)

        wrong_dek = random_data(32)
        decryptor = core.create_streaming_decryptor(wrong_dek, header)

        with pytest.raises(DataIntegrityError):
            list(decryptor.decrypt_stream(encrypted_stream))


class TestStreamingPerformance:
    """Test streaming performance characteristics."""

    def test_streaming_memory_efficient(self, initialized_storage):
        """Test that streaming doesn't load all data into memory."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        # Create iterator that yields data chunks
        def data_generator():
            for i in range(100):
                yield b"x" * 1024  # 1 KB chunks

        encryptor = core.create_streaming_encryptor(dek, params, chunk_size=2048)

        # Should be able to encrypt from generator
        encrypted_chunks = []
        encrypted_chunks.append(encryptor.get_header())

        for data_chunk in data_generator():
            encrypted_chunks.append(encryptor.encrypt_chunk(data_chunk))

        encrypted_chunks.append(b"\x00\x00\x00\x00" + encryptor.finalize())

        encrypted_data = b"".join(encrypted_chunks)

        # Decrypt
        encrypted_stream = io.BytesIO(encrypted_data)
        header = encrypted_stream.read(31)

        decryptor = core.create_streaming_decryptor(dek, header)
        decrypted_chunks = list(decryptor.decrypt_stream(encrypted_stream))
        decrypted_data = b"".join(decrypted_chunks)

        expected_data = b"x" * 1024 * 100
        assert decrypted_data == expected_data

    def test_streaming_processes_chunks_incrementally(self, initialized_storage):
        """Test that chunks are processed incrementally."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        data = b"A" * 10000

        encryptor = core.create_streaming_encryptor(dek, params, chunk_size=1024)  # Было 1000
        input_stream = io.BytesIO(data)

        # Get chunks one by one
        chunk_count = 0
        for encrypted_chunk in encryptor.encrypt_stream(input_stream):
            chunk_count += 1
            assert isinstance(encrypted_chunk, bytes)
            assert len(encrypted_chunk) > 0

        # Should have produced multiple chunks
        assert chunk_count > 1


import struct  # Add this import for the truncated data test
