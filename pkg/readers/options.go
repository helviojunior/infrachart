package readers

import (
    //"net/url"
)

// Options are global github.com/helviojunior/infrachartinfrachart options
type Options struct {
    // Logging is logging options
    Logging Logging
    
}

// Logging is log related options
type Logging struct {
    // Debug display debug level logging
    Debug bool
    // Debug display debug level logging
    DebugDb bool
    // LogScanErrors log errors related to scanning
    LogScanErrors bool
    // Silence all logging
    Silence bool
}

// NewDefaultOptions returns Options with some default values
func NewDefaultOptions() *Options {
    return &Options{
        Logging: Logging{
            Debug:         true,
            LogScanErrors: true,
        },
    }
}