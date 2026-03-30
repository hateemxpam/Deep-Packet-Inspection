#pragma once
#include "types.h"
#include <unordered_map>

class FlowTracker {
public:
    // Returns reference to existing or newly created flow
    Flow& getOrCreate(const FiveTuple& tuple);

    // Total number of tracked flows
    size_t flowCount() const;

    // Iterate over all flows (for reporting)
    const std::unordered_map<FiveTuple, Flow, FiveTupleHash>& flows() const;

private:
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows_;
};