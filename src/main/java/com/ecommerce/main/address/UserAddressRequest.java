package com.ecommerce.main.address;

import lombok.Data;

@Data
public class UserAddressRequest {
    private String title;
    private String fullAddress;
    private String city;
    private String district;
    private String postalCode;
    private String phone;
    private boolean isDefault;
}
