package com.fuelwise.app.auth.service;
import org.springframework.stereotype.Service;

import com.fuelwise.app.util.Haversine;

@Service
public class LocationMathService {
    public double getDistanceBetweenPoints(double lat1, double lon1, double lat2, double lon2) {
        return Haversine.calculateDistance(lat1, lon1, lat2, lon2);
    }
}