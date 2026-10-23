package dev.chimera.core;

/** Receives generated resources that must be written into the output jar. */
public interface ResourceSink {
    void put(String name, byte[] data);
}
