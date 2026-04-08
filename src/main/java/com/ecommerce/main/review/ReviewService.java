package com.ecommerce.main.review;

import com.ecommerce.main.product.Product;
import com.ecommerce.main.product.ProductRepository;
import com.ecommerce.main.user.Role;
import com.ecommerce.main.user.User;
import com.ecommerce.main.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class ReviewService {

    private final ReviewRepository reviewRepository;
    private final ProductRepository productRepository;
    private final UserRepository userRepository;

    /** Individual: yorum yaz */
    @Transactional
    public ReviewResponse create(String email, ReviewRequest request) {
        if (reviewRepository.existsByUserEmailAndProductId(email, request.getProductId())) {
            throw new IllegalStateException("You have already reviewed this product");
        }

        User user = findUser(email);
        Product product = productRepository.findById(request.getProductId())
                .orElseThrow(() -> new IllegalArgumentException("Product not found: " + request.getProductId()));

        String sentiment = deriveSentiment(request.getStarRating());

        Review review = Review.builder()
                .user(user)
                .product(product)
                .starRating(request.getStarRating())
                .comment(request.getComment())
                .sentiment(sentiment)
                .build();

        return ReviewResponse.from(reviewRepository.save(review));
    }

    /** Individual: kendi yorumunu güncelle */
    @Transactional
    public ReviewResponse update(Long id, String email, ReviewRequest request) {
        Review review = findReview(id);
        assertOwner(review, email);

        review.setStarRating(request.getStarRating());
        review.setComment(request.getComment());
        review.setSentiment(deriveSentiment(request.getStarRating()));

        return ReviewResponse.from(reviewRepository.save(review));
    }

    /** Individual: kendi yorumunu sil */
    @Transactional
    public void delete(Long id, String email) {
        Review review = findReview(id);
        assertOwner(review, email);
        reviewRepository.delete(review);
    }

    /** Herkese açık: ürüne ait yorumları listele */
    @Transactional(readOnly = true)
    public Page<ReviewResponse> getByProduct(Long productId, Pageable pageable) {
        return reviewRepository.findByProductId(productId, pageable).map(ReviewResponse::from);
    }

    /** Individual: kendi yorumlarını listele */
    @Transactional(readOnly = true)
    public Page<ReviewResponse> getMyReviews(String email, Pageable pageable) {
        return reviewRepository.findByUserEmail(email, pageable).map(ReviewResponse::from);
    }

    /** Corporate/Admin: store'a ait tüm yorumlar */
    @Transactional(readOnly = true)
    public Page<ReviewResponse> getByStore(Long storeId, Pageable pageable) {
        return reviewRepository.findByProductStoreId(storeId, pageable).map(ReviewResponse::from);
    }

    /** Corporate/Admin: yoruma mağaza cevabı ekle */
    @Transactional
    public ReviewResponse respond(Long id, String email, String response) {
        Review review = findReview(id);
        User user = findUser(email);

        boolean isAdmin = user.getRoleType() == Role.ADMIN;
        boolean isStoreOwner = review.getProduct().getStore().getOwner().getEmail().equals(email);
        if (!isAdmin && !isStoreOwner) {
            throw new IllegalStateException("Access denied");
        }

        review.setStoreResponse(response);
        review.setStoreRespondedAt(LocalDateTime.now());
        return ReviewResponse.from(reviewRepository.save(review));
    }

    /** Helpful vote ekle */
    @Transactional
    public ReviewResponse vote(Long id, boolean helpful) {
        Review review = findReview(id);
        review.setTotalVotes(review.getTotalVotes() + 1);
        if (helpful) review.setHelpfulVotes(review.getHelpfulVotes() + 1);
        return ReviewResponse.from(reviewRepository.save(review));
    }

    private String deriveSentiment(int starRating) {
        if (starRating >= 4) return "POSITIVE";
        if (starRating == 3) return "NEUTRAL";
        return "NEGATIVE";
    }

    private Review findReview(Long id) {
        return reviewRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Review not found: " + id));
    }

    private User findUser(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + email));
    }

    private void assertOwner(Review review, String email) {
        if (!review.getUser().getEmail().equals(email)) {
            throw new IllegalStateException("Access denied");
        }
    }
}
