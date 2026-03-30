#include "flow_tracker.h"

Flow& FlowTracker::getOrCreate(const FiveTuple& tuple) {
    auto& flow = flows_[tuple];
    flow.tuple = tuple;
    return flow;
}

size_t FlowTracker::flowCount() const {
    return flows_.size();
}

const std::unordered_map<FiveTuple, Flow, FiveTupleHash>&
FlowTracker::flows() const {
    return flows_;
}